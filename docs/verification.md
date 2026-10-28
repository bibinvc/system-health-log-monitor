# Verification record

28 October 2026 — Windows, Python 3.12.14.

- `python -m unittest discover -s tests -v`: **10 tests passed**, including live loopback HTTP requests.
- `node --check static/app.js`: passed.
- Browser: loaded 30 synthetic samples and 18 synthetic log events; collected one sample and verified the count became 31.
- Browser: clicked a failed-login alert and verified four matching event IDs; cleared the filter, selected ERROR and verified four of 18 loaded events remained.
- Browser: searched for an absent term, restored all events and captured the dashboard screenshot.
- CLI real-local collection was checked separately, with its database outside the repository. No local metric readings or real log files are committed.
- Missing platform metrics are represented as null and tested; demo and imported events are separated and tested.

The initial restricted execution environment prevented temporary database/socket access. Tests were rerun with a writable temporary directory and loopback access; the full suite passed. No tests were skipped.

Not claimed: enterprise monitoring, SIEM integration, background agents, production load testing or machine-learning anomaly detection. This record documents the checks above only.
