"""Read-only system metrics and JSONL log analysis for a local portfolio lab."""
import argparse
import csv
import ctypes
import hashlib
import io
import json
import math
import os
import platform
import shutil
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent
SEVERITIES = ('INFO', 'WARNING', 'ERROR', 'CRITICAL')


def utcnow():
    return datetime.now(timezone.utc)


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError('timestamp must be an ISO 8601 string with a timezone.')
    try:
        dt = datetime.fromisoformat(value.replace('Z', '+00:00'))
    except ValueError:
        raise ValueError('Invalid ISO 8601 timestamp.') from None
    if dt.tzinfo is None:
        raise ValueError('Timestamp must include a timezone.')
    return dt.astimezone(timezone.utc)


def validate_event(value):
    if not isinstance(value, dict) or set(value) != {'timestamp', 'severity', 'source', 'event', 'message'}:
        raise ValueError('Each event needs exactly timestamp, severity, source, event and message.')
    result = {'timestamp': timestamp(value['timestamp']).isoformat(timespec='seconds')}
    for key, limit in (('severity', 8), ('source', 80), ('event', 80), ('message', 1000)):
        if not isinstance(value[key], str) or not value[key].strip() or len(value[key]) > limit:
            raise ValueError(f'Invalid {key}.')
        result[key] = value[key].strip()
    if result['severity'] not in SEVERITIES:
        raise ValueError('Unsupported severity.')
    return result


def parse_jsonl(raw):
    if len(raw.encode('utf-8')) > 1_048_576:
        raise ValueError('Import exceeds 1 MiB.')
    events = []
    for number, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            events.append(validate_event(json.loads(line)))
        except (ValueError, TypeError) as error:
            raise ValueError(f'Line {number}: {error}') from None
    if len(events) > 5000:
        raise ValueError('At most 5000 events per import.')
    return events


def memory_percent():
    try:
        if platform.system() == 'Windows':
            class MemoryStatus(ctypes.Structure):
                _fields_ = [('length', ctypes.c_ulong), ('load', ctypes.c_ulong)] + [(name, ctypes.c_ulonglong) for name in
                    ('total_physical', 'available_physical', 'total_page', 'available_page', 'total_virtual', 'available_virtual', 'extended')]
            status = MemoryStatus()
            status.length = ctypes.sizeof(status)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(status)):
                return float(status.load)
        elif platform.system() == 'Linux':
            fields = {}
            for line in Path('/proc/meminfo').read_text().splitlines():
                key, value = line.split(':', 1)
                fields[key] = int(value.split()[0])
            return round(100 * (1 - fields['MemAvailable'] / fields['MemTotal']), 2)
    except (OSError, KeyError, ValueError, AttributeError, ZeroDivisionError):
        pass
    return None


def collect(path):
    usage = shutil.disk_usage(path)
    try:
        load = round(os.getloadavg()[0], 2)
    except (OSError, AttributeError):
        load = None
    return {'at': utcnow().isoformat(timespec='seconds'), 'mode': 'local',
            'disk_percent': round(100 * usage.used / usage.total, 2),
            'disk_free_gib': round(usage.free / 1024 ** 3, 2),
            'memory_percent': memory_percent(), 'load_1m': load}


def demo_sample(at, index):
    return {'at': at.isoformat(timespec='seconds'), 'mode': 'demo',
            'disk_percent': round(67 + 3 * math.sin(index / 3), 2),
            'disk_free_gib': round(100 * (1 - (67 + 3 * math.sin(index / 3)) / 100), 2),
            'memory_percent': round(48 + 12 * math.sin(index / 5), 2), 'load_1m': round(0.9 + 0.4 * math.sin(index / 2), 2)}


def rules(events, sample, reference=None, disk_limit=85, burst_limit=5, login_limit=3):
    reference = reference or utcnow()
    window = [e for e in events if reference - timedelta(minutes=10) <= timestamp(e['timestamp']) <= reference]
    alerts = []
    if sample and sample['disk_percent'] is not None and sample['disk_percent'] >= disk_limit:
        alerts.append({'rule': 'Disk usage', 'severity': 'WARNING', 'detail': f"{sample['disk_percent']}% used (threshold {disk_limit}%).", 'event_ids': []})
    errors = [e for e in window if e['severity'] in ('ERROR', 'CRITICAL')]
    failures = [e for e in window if e['event'] == 'login_failed']
    for name, values, limit in [('Error burst · 10 min', errors, burst_limit), ('Failed logins · 10 min', failures, login_limit)]:
        if len(values) >= limit:
            alerts.append({'rule': name, 'severity': 'WARNING', 'detail': f'{len(values)} matching events (threshold {limit}).', 'event_ids': [e.get('id') for e in values]})
    return alerts


class Store:
    def __init__(self, path):
        self.path = str(path)
        with self.connect() as db:
            db.executescript('''
                CREATE TABLE IF NOT EXISTS samples(id INTEGER PRIMARY KEY, at TEXT NOT NULL, mode TEXT NOT NULL,
                    disk_percent REAL, disk_free_gib REAL, memory_percent REAL, load_1m REAL);
                CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY, fingerprint TEXT NOT NULL UNIQUE,
                    timestamp TEXT NOT NULL, severity TEXT NOT NULL, source TEXT NOT NULL,
                    event TEXT NOT NULL, message TEXT NOT NULL, mode TEXT NOT NULL);
            ''')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        try:
            with db:
                yield db
        finally:
            db.close()

    def save_sample(self, sample):
        with self.connect() as db:
            db.execute('INSERT INTO samples(at,mode,disk_percent,disk_free_gib,memory_percent,load_1m) VALUES(?,?,?,?,?,?)',
                       [sample[k] for k in ('at', 'mode', 'disk_percent', 'disk_free_gib', 'memory_percent', 'load_1m')])

    def import_events(self, events, mode='imported'):
        if mode not in ('demo', 'imported'):
            raise ValueError('Invalid event provenance.')
        checked = [validate_event(event) for event in events]
        inserted = 0
        with self.connect() as db:
            for event in checked:
                fingerprint = hashlib.sha256((mode + json.dumps(event, sort_keys=True)).encode()).hexdigest()
                inserted += db.execute('INSERT OR IGNORE INTO events(fingerprint,timestamp,severity,source,event,message,mode) VALUES(?,?,?,?,?,?,?)',
                    [fingerprint] + [event[k] for k in ('timestamp','severity','source','event','message')] + [mode]).rowcount
        return inserted

    def state(self, mode='demo', reference=None):
        with self.connect() as db:
            samples = [dict(row) for row in db.execute('SELECT * FROM samples WHERE mode=? ORDER BY at DESC,id DESC LIMIT 60', (mode,))][::-1]
            provenance = 'demo' if mode == 'demo' else 'imported'
            # Rules evaluate the full 10-minute window; the event table view alone is capped at 500.
            ref = reference or utcnow()
            since = (ref - timedelta(minutes=10)).isoformat(timespec='seconds')
            recent = [dict(row) for row in db.execute('SELECT * FROM events WHERE mode=? AND timestamp>=? AND timestamp<=? ORDER BY timestamp DESC,id DESC',
                         (provenance, since, ref.isoformat(timespec='seconds')))]
            events = [dict(row) for row in db.execute('SELECT * FROM events WHERE mode=? ORDER BY timestamp DESC,id DESC LIMIT 500', (provenance,))]
        latest = samples[-1] if samples else None
        return {'mode': mode, 'samples': samples, 'latest': latest, 'events': events,
                'alerts': rules(recent, latest, ref), 'checked_at': ref.isoformat(timespec='seconds')}

    def seed(self):
        with self.connect() as db:
            if db.execute("SELECT count(*) FROM samples WHERE mode='demo'").fetchone()[0]:
                return False
        at = utcnow()
        for i in range(30):
            self.save_sample(demo_sample(at - timedelta(minutes=29-i), i))
        events = []
        for i in range(18):
            failure = i in (10, 12, 14, 16)
            error = i >= 11 and i % 2 == 1
            events.append({'timestamp': (at - timedelta(minutes=17-i)).isoformat(timespec='seconds'),
                'severity': 'ERROR' if error else 'WARNING' if failure else 'INFO',
                'source': 'demo-auth' if failure else 'demo-backup' if error else 'demo-agent',
                'event': 'login_failed' if failure else 'backup_failed' if error else 'heartbeat',
                'message': 'Synthetic sign-in failure for lab-user' if failure else 'Synthetic backup retry required' if error else 'Synthetic health check completed'})
        self.import_events(events, 'demo')
        return True


def export_csv(rows):
    output = io.StringIO(newline='')
    if rows:
        fields = [k for k in rows[0] if k != 'fingerprint']
        writer = csv.DictWriter(output, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for row in rows:
            writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v for k, v in row.items()})
    return output.getvalue().encode('utf-8-sig')


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def local(self):
        return self.headers.get('Host') in {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}

    def send(self, status, data, mime='application/json; charset=utf-8'):
        body = data if isinstance(data, bytes) else json.dumps(data, ensure_ascii=False).encode()
        self.send_response(status)
        for key, value in {'Content-Type': mime, 'Content-Length': str(len(body)), 'Cache-Control': 'no-store',
                'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'; base-uri 'none'"}.items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.local():
            return self.send(403, {'error': 'Local access only.'})
        path = urlsplit(self.path).path
        if path == '/api/state':
            return self.send(200, self.server.store.state(self.server.mode))
        if path == '/export/events.csv':
            return self.send(200, export_csv(self.server.store.state(self.server.mode)['events']), 'text/csv; charset=utf-8')
        files = {'/': ('index.html', 'text/html'), '/app.js': ('app.js', 'text/javascript'), '/style.css': ('style.css', 'text/css')}
        if path not in files:
            return self.send(404, {'error': 'Not found.'})
        filename, mime = files[path]
        self.send(200, (ROOT / 'static' / filename).read_bytes(), mime + '; charset=utf-8')

    def do_POST(self):
        port = self.server.server_port
        if not self.local() or self.headers.get('Origin') not in (None, f'http://localhost:{port}', f'http://127.0.0.1:{port}') or self.headers.get('X-Local-Client') != '1':
            return self.send(403, {'error': 'Use the local dashboard.'})
        if urlsplit(self.path).path != '/api/collect':
            return self.send(404, {'error': 'Not found.'})
        # No web endpoint accepts file paths or arbitrary commands.
        if self.headers.get_content_type() != 'application/json':
            return self.send(415, {'error': 'JSON required.'})
        try:
            size = int(self.headers.get('Content-Length', '0'))
            if not 0 < size <= 100:
                return self.send(413, {'error': 'Expected a small JSON body.'})
            if json.loads(self.rfile.read(size)) != {}:
                raise ValueError('Expected an empty JSON object.')
            if self.server.mode == 'demo':
                count = len(self.server.store.state('demo')['samples'])
                sample = demo_sample(utcnow(), count)
            else:
                sample = collect(self.server.disk_path)
            self.server.store.save_sample(sample)
            self.send(201, {'ok': True})
        except (ValueError, UnicodeDecodeError) as error:
            self.send(400, {'error': str(error)})
        except OSError:
            self.send(503, {'error': 'Local metrics unavailable. Check the configured disk path.'})


def make_server(path, port=9876, mode='demo', disk_path=None):
    server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
    server.store = Store(path)
    server.mode = mode
    server.disk_path = disk_path or Path.cwd().anchor
    return server


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('serve', 'collect', 'import-logs', 'report'), nargs='?', default='serve')
    parser.add_argument('--db', default=str(ROOT / 'data' / 'monitor.sqlite3'))
    parser.add_argument('--mode', choices=('demo', 'local'), default='demo')
    parser.add_argument('--port', type=int, default=9876)
    parser.add_argument('--disk-path', default=Path.cwd().anchor)
    parser.add_argument('--file', type=Path, help='JSONL file for import-logs; read only from this CLI.')
    args = parser.parse_args()
    Path(args.db).parent.mkdir(parents=True, exist_ok=True)
    store = Store(args.db)
    if args.command == 'import-logs':
        if args.file is None or args.file.stat().st_size > 1_048_576:
            parser.error('Supply --file with a JSONL file up to 1 MiB.')
        try:
            print(f'Imported {store.import_events(parse_jsonl(args.file.read_text(encoding="utf-8")))} new events.')
        except (ValueError, OSError) as error:
            parser.error(str(error))
    elif args.command == 'collect':
        sample = collect(args.disk_path)
        store.save_sample(sample)
        print(json.dumps(sample, indent=2))
    elif args.command == 'report':
        print(json.dumps(store.state(args.mode), indent=2))
    else:
        server = make_server(args.db, args.port, args.mode, args.disk_path)
        if args.mode == 'demo':
            server.store.seed()
        else:
            server.store.save_sample(collect(args.disk_path))
        print(f'Health & Log Lab ({args.mode}): http://127.0.0.1:{server.server_port} (Ctrl+C to stop)', flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()


if __name__ == '__main__':
    main()
