# hhc-report

Companion CLI for the `http-hardening-check` Nmap script. It reads Nmap XML
(`nmap -oX`) and writes table, JSON, CSV, Markdown, HTML or SARIF output, then
exits non-zero when findings cross a threshold so a pipeline can stop.

```bash
pip install ./reporter
hhc-report scan.xml --format html --output report.html
hhc-report scan.xml --fail-on high
```

Python 3.10+, standard library only. Full documentation:
[docs/reporter.md](https://github.com/VijaysinghPuwar/http-hardening-nmap-nse/blob/main/docs/reporter.md).
