# Automated Log Parser (Prototype)

A small Python CLI tool that parses common log lines and prints a basic security-oriented report.

## What it does

- Reads a log file line-by-line
- Tries to parse each line as either:
  - **Apache access log (common format)**:
    `IP - - [timestamp] "request" status size`
  - **Simple syslog-like line**:
    `Mon DD HH:MM:SS host message`
- Prints a console report with:
  - Total entries analyzed
  - Top IP addresses (for Apache-format entries)
  - Suspicious activity matches (keyword/regex scan)
  - HTTP status code distribution (for Apache-format entries)

> Note: The `is_suspicious_ip()` function is a placeholder hook. It currently does not automatically flag public IPs as suspicious.

## Project structure

- `log_parser.py` — main CLI script
- `sample_logs/` — example logs for quick testing
- `requirements.txt` — minimal dependencies (color output)

## Requirements

- Python 3.9+ recommended

### Dependencies

- `colorama`

Install:

```bash
pip install -r requirements.txt
