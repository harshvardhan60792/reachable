# Evidence

Output this tool produced against real projects, kept because a triage tool's claims are only
worth what its results on unfamiliar code are worth.

## Corpus runs

`reachable` has been run over 22 Python repositories — Django, Celery, Scrapy, aiohttp,
gunicorn, pip, sqlmap, mitmproxy, FastAPI, Flask, requests and others — with Semgrep live.
Results and the defects that run exposed are written up in [VERIFICATION.md](../../VERIFICATION.md).

Two of the nine defects in that file were found only because the tool was pointed at code it
had never seen. The test suite passed the whole time.
