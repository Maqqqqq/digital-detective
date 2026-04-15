# Digital Detective CLI

Digital Detective is a Python CLI tool for quick OSINT-style lookups against usernames, IP addresses, and given names.

## Author
- Markus Stamm

## Educational Use Only

This project is for education and authorized research only. Do not use it to collect, enrich, or publish information about people without permission or a lawful reason.

## Features
- **Username check** – Probe a configurable list of platforms to see if a username appears to exist.
- **IP lookup** – Query both [IP-API](https://ip-api.com/) and [ipwho.is](https://ipwho.is/) for ISP, organization, and location details.
- **Name search** – Scrape FastPeopleSearch (via Scrape.do) for possible matches, including age, location, phone, and profile URL when available.

## Limitation

Full name search is intentionally limited and incomplete because access to legal name-search databases is restricted. This feature is a constrained learning exercise, not a complete investigation tool.

## Getting Started

### Requirements
- Python 3.10+
- Pip or another dependency manager
- A Scrape.do API token (for name searches)

### Unix/Linux/Mac Setup
```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```
### Windows Setup
```bash
py -3 -m venv .venv
source .venv/Scripts/activate
pip install -r requirements.txt
```

### Usage

```bash
# Username search across configured platforms
python3 data_digger.py -un recyclops

# IP address search (IP-API + ipwho.is cross-reference)
python3 data_digger.py -ip 8.8.8.8

# Name search (requires SCRAPE_API_KEY)
python3 data_digger.py -n "John Smith"

# Combine lookups — each section runs sequentially
python3 data_digger.py -n "John Smith" -ip 8.8.8.8 -un recyclops

# Add --visualize to any command for simple bar charts
python3 data_digger.py -n "John Smith" --visualize
```

You can provide any mix of `-un`, `-ip`, and `-n` in a single run; the CLI processes them in the order shown above. Invalid inputs short-circuit that specific lookup but let the remaining searches continue. Running without arguments still displays the Typer usage screen.

### Customising Platforms

You can add or remove platforms by editing `platforms.yml`. Each entry needs a human-readable `name` and a `url_pattern` that includes `{username}`.
