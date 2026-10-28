import http.client
import json
import tempfile
import threading
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from monitor import Store, collect, export_csv, make_server, parse_jsonl, rules, validate_event

AT = datetime(2026, 10, 28, 12, tzinfo=timezone.utc)


def event(**patches):
    return {'timestamp': AT.isoformat(), 'severity': 'ERROR', 'source': 'test', 'event': 'login_failed', 'message': 'Synthetic test event', **patches}


class DataTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name)/'monitor.db'
        self.store = Store(self.path)

    def tearDown(self):
        self.tmp.cleanup()

    def test_strict_event_validation(self):
        for e in (event(timestamp='yesterday'), event(timestamp='2026-10-28T12:00:00'), event(severity='unknown'), event(message=''), {**event(), 'extra': 1}):
            with self.subTest(event=e), self.assertRaises(ValueError):
                validate_event(e)
        self.assertTrue(validate_event(event(timestamp='2026-10-28T14:00:00+02:00'))['timestamp'].startswith('2026-10-28T12:00:00'))

    def test_jsonl_line_number_and_size(self):
        with self.assertRaisesRegex(ValueError, 'Line 2'):
            parse_jsonl(json.dumps(event())+'\ninvalid')
        with self.assertRaisesRegex(ValueError, '1 MiB'):
            parse_jsonl(' '*1_048_577)
        self.assertEqual(len(parse_jsonl('\n'+json.dumps(event())+'\n')), 1)

    def test_idempotent_atomic_import(self):
        self.assertEqual(self.store.import_events([event()]), 1)
        self.assertEqual(self.store.import_events([event()]), 0)
        with self.assertRaises(ValueError):
            self.store.import_events([event(message='new'), event(severity='bad')])
        self.assertEqual(len(Store(self.path).state('local', AT)['events']), 1)

    def test_alert_thresholds_window_and_future_exclusion(self):
        recent = [{**event(message=str(i)), 'id': i} for i in range(5)]
        old = event(timestamp=(AT-timedelta(minutes=11)).isoformat())
        future = event(timestamp=(AT+timedelta(seconds=1)).isoformat())
        result = rules(recent+[old, future], {'disk_percent': 85}, AT)
        self.assertEqual(len(result), 3)
        self.assertEqual(result[1]['event_ids'], list(range(5)))
        self.assertEqual(rules([old, future], {'disk_percent': 84.9}, AT), [])

    def test_rule_evaluation_is_not_truncated_by_table_limit(self):
        self.store.import_events([event(message=f'event {i}') for i in range(505)])
        state = self.store.state('local', AT)
        self.assertEqual(len(state['events']), 500)
        self.assertEqual(len(state['alerts'][0]['event_ids']), 505)

    def test_provenance_separation_and_idempotent_demo(self):
        self.assertTrue(self.store.seed())
        self.assertFalse(self.store.seed())
        self.store.import_events([event()])
        self.assertEqual(len(self.store.state('demo')['events']), 18)
        self.assertEqual(len(self.store.state('local', AT)['events']), 1)
        self.assertTrue(all(s['mode'] == 'demo' for s in self.store.state('demo')['samples']))

    def test_collection_does_not_invent_unavailable_metrics(self):
        with patch('monitor.os.getloadavg', create=True, side_effect=OSError), patch('monitor.memory_percent', return_value=None):
            sample = collect(self.tmp.name)
        self.assertIsNone(sample['memory_percent'])
        self.assertIsNone(sample['load_1m'])
        self.assertEqual(sample['mode'], 'local')
        self.assertTrue(0 <= sample['disk_percent'] <= 100)
        self.store.save_sample(sample)
        self.assertIsNone(self.store.state('local')['latest']['memory_percent'])

    def test_csv_escapes_formulas(self):
        result = export_csv([{'message': '@SUM(1)', 'fingerprint': 'private-implementation-detail'}]).decode('utf-8-sig')
        self.assertIn("'@SUM(1)", result)
        self.assertNotIn('fingerprint', result)


class HttpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.server = make_server(Path(self.tmp.name)/'http.db', 0)
        self.server.store.seed()
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.tmp.cleanup()

    def request(self, method, path, body=None, headers=None):
        conn = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        conn.request(method, path, body, headers or {})
        res = conn.getresponse()
        result = res.status, res.read()
        conn.close()
        return result

    def test_dashboard_and_collect(self):
        self.assertEqual(self.request('GET', '/')[0], 200)
        headers = {'Content-Type': 'application/json', 'X-Local-Client': '1'}
        self.assertEqual(self.request('POST', '/api/collect', '{}', headers)[0], 201)
        state = json.loads(self.request('GET', '/api/state')[1])
        self.assertEqual(state['mode'], 'demo')
        self.assertEqual(len(state['samples']), 31)
        self.assertEqual(self.request('GET', '/export/events.csv')[0], 200)

    def test_local_boundary_and_no_file_access_api(self):
        self.assertEqual(self.request('GET', '/', headers={'Host': 'attacker.invalid'})[0], 403)
        headers = {'Content-Type': 'application/json', 'X-Local-Client': '1', 'Origin': 'https://example.invalid'}
        self.assertEqual(self.request('POST', '/api/collect', '{}', headers)[0], 403)
        headers.pop('Origin')
        self.assertEqual(self.request('POST', '/api/collect', '{"file":"secret"}', headers)[0], 400)
        self.assertEqual(self.request('GET', '/../../monitor.py')[0], 404)


if __name__ == '__main__':
    unittest.main()
