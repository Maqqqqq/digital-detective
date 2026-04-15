#!/usr/bin/env python3
"""
Digital Detective CLI — Username & IP checker

Usage:
    python data_digger.py -un recyclops
    python data_digger.py -ip 8.8.8.8
    python data_digger.py -n "John Smith"
"""
from pathlib import Path
import ipaddress
import re
import time
import os
from dataclasses import dataclass
from urllib.parse import quote, urlencode, urlparse, unquote
from typing import Dict, List, Optional
from difflib import SequenceMatcher
from threading import Lock
from collections import Counter
from dotenv import load_dotenv

import requests
import typer
import yaml
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from bs4 import BeautifulSoup

load_dotenv()
app = typer.Typer(add_completion=False, no_args_is_help=True)
console = Console()

# Shared HTTP session for all network calls.
SESSION = requests.Session()
SESSION.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Accept": "*/*",
})

REQUEST_LOCK = Lock()
LAST_REQUEST_TS = 0.0
RATE_LIMIT_SECONDS = float(os.getenv("DIGITAL_DETECTIVE_RATE_SECONDS", "0.25"))
MAX_RETRIES = int(os.getenv("DIGITAL_DETECTIVE_RETRIES", "3"))
BACKOFF_FACTOR = float(os.getenv("DIGITAL_DETECTIVE_BACKOFF", "1.5"))
RETRY_STATUS = {429, 500, 502, 503, 504}

IP_API_URL = "http://ip-api.com/json/{ip}"
IP_API_FIELDS = "status,message,query,isp,org,city,regionName,country"
IP_WHOIS_URL = "https://ipwho.is/{ip}"
FILENAME_PREFIXES = {
    "name": "n_",
    "ip": "ip_",
    "un": "un_",
}


def rate_limited_request(method: str, url: str, *, timeout: int = 10, max_retries: int = MAX_RETRIES, **kwargs) -> requests.Response:
    """Perform an HTTP request with a global rate limit and simple exponential backoff."""
    global LAST_REQUEST_TS
    attempt = 0
    while attempt < max_retries:
        with REQUEST_LOCK:
            delay = RATE_LIMIT_SECONDS - (time.monotonic() - LAST_REQUEST_TS)
        if delay > 0:
            time.sleep(delay)
        try:
            response = SESSION.request(method, url, timeout=timeout, **kwargs)
        except requests.RequestException:
            attempt += 1
            time.sleep(BACKOFF_FACTOR ** attempt)
            continue

        with REQUEST_LOCK:
            LAST_REQUEST_TS = time.monotonic()

        if response.status_code in RETRY_STATUS and attempt < max_retries - 1:
            attempt += 1
            time.sleep(BACKOFF_FACTOR ** attempt)
            continue
        return response

    raise requests.RequestException(f"Failed to fetch {url} after {max_retries} attempts.")


def try_head(url: str, timeout: int = 8):
    """Try HEAD then fallback to GET for sites that block HEAD."""
    try:
        h = rate_limited_request("HEAD", url, timeout=timeout, allow_redirects=True)
        if h.status_code in (200, 301, 302):
            return True, h.status_code
        g = rate_limited_request("GET", url, timeout=timeout, stream=True)
        ok = g.status_code in (200, 301, 302)
        return ok, g.status_code
    except requests.RequestException:
        return False, 0


def load_platforms(path: Path = Path("platforms.yml")):
    if not path.exists():
        raise FileNotFoundError(f"{path} missing. Create platforms.yml in project root.")
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(cfg, dict):
        return []
    platforms = cfg.get("platforms")
    return platforms if isinstance(platforms, list) else []


def check_username(username: str, delay: float = 0.25):
    username = username.lstrip("@")
    encoded_username = quote(username, safe="") if username else ""
    results = []
    platforms = load_platforms()
    for p in platforms:
        url = p["url_pattern"].format(username=encoded_username)
        ok, code = try_head(url)
        results.append({"name": p["name"], "url": url, "exists": ok, "status": code})
        time.sleep(delay)
    return {"input": username, "platforms": results}


def table_for_username(res: dict) -> Table:
    t = Table(title=f"Username: {res['input']}")
    t.add_column("Platform", no_wrap=True)
    t.add_column("Exists")
    t.add_column("HTTP")
    t.add_column("URL")
    for p in res["platforms"]:
        t.add_row(
            p["name"],
            "yes" if p["exists"] else "no",
            str(p["status"]),
            p["url"],
        )
    return t


def fetch_ip_details(ip_str: str) -> Optional[Dict[str, str]]:
    try:
        resp = rate_limited_request(
            "GET",
            IP_API_URL.format(ip=ip_str),
            params={"fields": IP_API_FIELDS},
            timeout=8,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    if data.get("status") != "success":
        return None

    isp = data.get("isp") or data.get("org") or "Unknown ISP"
    location = ", ".join(filter(None, [data.get("city"), data.get("regionName"), data.get("country")]))
    if not location:
        location = "Location not available"
    return {"ip": ip_str, "isp": isp, "location": location}


def fetch_ipwhois_details(ip_str: str) -> Optional[Dict[str, str]]:
    """Fetch supplementary IP data from ipwho.is."""
    try:
        resp = rate_limited_request("GET", IP_WHOIS_URL.format(ip=ip_str), timeout=8)
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()
    except ValueError:
        return None

    if data.get("success") is False:
        return None

    location = ", ".join(filter(None, [data.get("city"), data.get("region"), data.get("country")]))
    return {
        "continent": data.get("continent"),
        "country": data.get("country"),
        "location": location or None,
        "timezone": data.get("timezone", {}).get("id") if isinstance(data.get("timezone"), dict) else data.get("timezone"),
        "org": data.get("connection", {}).get("org") if isinstance(data.get("connection"), dict) else data.get("org"),
        "type": data.get("type"),
        "source": "ipwho.is",
    }


def lookup_ip(ip_value: str) -> Dict[str, str]:
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError as exc:
        raise ValueError(f"Invalid IP address: {ip_value}") from exc

    ip_str = str(ip_obj)
    api_result = fetch_ip_details(ip_str)
    if api_result:
        secondary = fetch_ipwhois_details(ip_str)
        if secondary:
            combined_location = api_result["location"]
            if secondary.get("location"):
                combined_location = secondary["location"]
            api_result.update({
                "location": combined_location,
                "org": secondary.get("org"),
                "timezone": secondary.get("timezone"),
                "network_type": secondary.get("type"),
                "country": secondary.get("country"),
                "continent": secondary.get("continent"),
                "secondary_source": secondary.get("source"),
            })
        return api_result

    return {
        "ip": ip_str,
        "isp": "Unknown ISP (lookup failed)",
        "location": "Location unavailable",
    }


def safe_slug(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", value.lower()).strip("_")


def normalize_person_name(value: str) -> str:
    lowered = value.lower()
    without_punctuation = re.sub(r"[^\w\s]", " ", lowered)
    collapsed_whitespace = re.sub(r"\s+", " ", without_punctuation)
    return collapsed_whitespace.strip()


def extract_age(value: str) -> Optional[str]:
    if not value:
        return None
    match = re.search(r'\b(\d{1,3})\b', value)
    if match:
        return match.group(1)
    return None


def extract_phone(value: str) -> Optional[str]:
    if not value:
        return None
    phone_match = re.search(r'(\(?\d{3}\)?[\s\.-]?\d{3}[\s\.-]?\d{4})', value)
    if phone_match:
        return phone_match.group(1)
    return None


def name_from_url(url: str) -> Optional[str]:
    if not url:
        return None
    parsed = urlparse(url)
    slug = parsed.path or url
    segments = [segment for segment in slug.split("/") if segment]
    if not segments:
        return None
    candidate = segments[-1]
    candidate = candidate.split("_")[0]
    candidate = unquote(candidate)
    words = [part for part in candidate.replace("-", " ").split() if part]
    if not words:
        return None
    return " ".join(word.capitalize() for word in words)


def clean_display_name(raw_name: str, url: Optional[str], container) -> str:
    invalid_name_pattern = re.compile(r'^\s*(age|view|info)\b', re.I)
    candidate = (raw_name or "").strip()
    if candidate and not invalid_name_pattern.match(candidate):
        return candidate

    if url:
        inferred = name_from_url(url)
        if inferred and not invalid_name_pattern.match(inferred):
            return inferred

    if container and hasattr(container, "find"):
        alt_link = container.find('a', href=re.compile(r'/person/', re.I))
        if alt_link:
            text = alt_link.get_text(strip=True)
            if text and not invalid_name_pattern.match(text):
                return text
        header = container.find(['h1', 'h2', 'h3', 'h4'])
        if header:
            text = header.get_text(strip=True)
            if text and not invalid_name_pattern.match(text):
                return text

    return "Name unavailable"


def strip_location_from_name(name: str, location: Optional[str]) -> str:
    if not name or not location:
        return name
    normalized_name = re.sub(r"\s+", " ", name).strip()
    normalized_location = re.sub(r"\s+", " ", location).strip()

    # Remove exact trailing match of the full location string.
    if normalized_name.lower().endswith(normalized_location.lower()):
        normalized_name = normalized_name[:-len(normalized_location)].rstrip(", -")

    # Remove location tokens wherever they linger at the end.
    name_tokens = re.findall(r"[A-Za-z0-9']+", normalized_name)
    location_tokens = re.findall(r"[A-Za-z0-9']+", normalized_location)
    i = len(name_tokens)
    j = len(location_tokens)
    while i > 0 and j > 0 and name_tokens[i - 1].lower() == location_tokens[j - 1].lower():
        i -= 1
        j -= 1
    if i < len(name_tokens):
        normalized_name = " ".join(name_tokens[:i])

    return normalized_name or name.strip()


def normalize_profile_url(href: Optional[str]) -> Optional[str]:
    if not href:
        return None
    href = href.strip()
    if not href or href.lower().startswith("javascript:"):
        return None
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("http://") or href.startswith("https://"):
        return href
    if not href.startswith("/"):
        href = "/" + href
    return f"https://www.fastpeoplesearch.com{href}"


def name_match_score(target: str, candidate: str) -> float:
    if not target or not candidate:
        return 0.0
    if candidate == target:
        return 3.0
    if target in candidate or candidate in target:
        return 2.0
    target_tokens = target.split()
    found_tokens = candidate.split()
    if target_tokens and all(token in found_tokens for token in target_tokens):
        return 1.8
    if target_tokens:
        overlap = sum(1 for token in target_tokens if token in found_tokens)
        if overlap >= max(1, len(target_tokens) - 1) and target_tokens[-1] in found_tokens:
            return 1.5
    return SequenceMatcher(None, target, candidate).ratio()


@dataclass
class PersonRecord:
    name: str = "Name unavailable"
    age: Optional[str] = None
    location: Optional[str] = None
    phone: Optional[str] = None
    url: Optional[str] = None
    score: float = 0.0

    def to_dict(self) -> Dict[str, Optional[str]]:
        return {
            "name": self.name or "Name unavailable",
            "age": self.age,
            "location": self.location,
            "phone": self.phone,
            "url": self.url,
        }


def iter_person_nodes(soup: BeautifulSoup):
    cards = soup.select("div.card, div.card-block")
    if cards:
        for card in cards:
            yield card
    else:
        for link in soup.select("a[href^='/person/']"):
            yield link


def resolve_container(node):
    if not hasattr(node, "name"):
        return None
    if node.name != "a":
        return node
    current = getattr(node, "parent", None)
    for _ in range(4):
        if not current:
            break
        if getattr(current, "name", None) in {"div", "li", "article", "section"}:
            return current
        current = getattr(current, "parent", None)
    return getattr(node, "parent", None)


def extract_age_from_container(container) -> Optional[str]:
    if not container or not hasattr(container, "find_all"):
        return None
    texts: List[str] = []
    texts.extend(filter(None, container.find_all(string=re.compile(r"Age[:\s]+\d+", re.I))))
    for node in container.find_all(class_=re.compile("age", re.I)):
        texts.append(node.get_text(" ", strip=True))
    texts.append(container.get_text(" ", strip=True))
    for text in texts:
        age = extract_age(text)
        if age:
            return age
    return None


def extract_location_from_container(container) -> Optional[str]:
    if not container or not hasattr(container, "find"):
        return None
    node = container.find(class_=re.compile("address|location", re.I))
    if node:
        text = node.get_text(" ", strip=True)
        if text:
            return text
    text = container.get_text(" ", strip=True)
    match = re.search(r"[A-Za-z\s]+\s*,\s*[A-Z]{2}\b", text)
    return match.group(0) if match else None


def extract_phone_from_container(container) -> Optional[str]:
    if not container or not hasattr(container, "get_text"):
        return None
    nodes = container.find_all(class_=re.compile("phone", re.I)) if hasattr(container, "find_all") else []
    for node in nodes:
        phone = extract_phone(node.get_text(" ", strip=True))
        if phone:
            return phone
    if hasattr(container, "find_all"):
        tel_links = container.find_all("a", href=re.compile(r"^tel:", re.I))
        for link in tel_links:
            phone = extract_phone(link.get_text(" ", strip=True) or link.get("href", ""))
            if phone:
                return phone
    return extract_phone(container.get_text(" ", strip=True))


def clean_location(value: Optional[str], name: str) -> Optional[str]:
    if not value:
        return value
    value = re.sub(r"\s+", " ", value).strip()
    if not value:
        return None
    if value.lower().startswith(name.lower()):
        remainder = value[len(name):].strip(", -")
        if remainder:
            return remainder
        return None
    tokens_value = re.findall(r"[A-Za-z0-9']+", value)
    tokens_name = re.findall(r"[A-Za-z0-9']+", name)
    if tokens_value[: len(tokens_name)] == tokens_name:
        leftover = tokens_value[len(tokens_name):]
        if leftover:
            return " ".join(leftover)
        return None
    return value


def build_person_record(node, target_norm: str) -> Optional[PersonRecord]:
    container = resolve_container(node) or node
    if not container:
        return None

    name_element = node if getattr(node, "name", None) == "a" else None
    if not name_element and hasattr(container, "select_one"):
        for selector in (
            "a[href^='/person/']",
            "h3",
            "a.card-title",
            "h2",
            "div.name",
        ):
            candidate = container.select_one(selector)
            if candidate and candidate.get_text(strip=True):
                name_element = candidate
                break
    raw_name = name_element.get_text(" ", strip=True) if name_element else container.get_text(" ", strip=True)

    url = None
    if name_element and name_element.name == "a":
        url = normalize_profile_url(name_element.get("href"))
    if not url and getattr(node, "name", None) == "a":
        url = normalize_profile_url(node.get("href"))
    if not url and hasattr(container, "get"):
        data_url = container.get("data-profile-url") or container.get("data-url")
        url = normalize_profile_url(data_url)
    if not url and hasattr(container, "find_all"):
        for anchor in container.find_all("a", href=True):
            url = normalize_profile_url(anchor.get("href"))
            if url:
                break

    display_name = clean_display_name(raw_name, url, container)
    location = extract_location_from_container(container)
    location = clean_location(location, display_name)
    if location:
        display_name = strip_location_from_name(display_name, location)

    normalized_found = normalize_person_name(display_name)
    score = name_match_score(target_norm, normalized_found)
    if display_name == "Name unavailable":
        score = 0.0

    record = PersonRecord(
        name=display_name,
        age=extract_age_from_container(container),
        location=location,
        phone=extract_phone_from_container(container),
        url=url,
        score=score,
    )
    return record


def render_bar_panel(data: Dict[str, int], title: str) -> None:
    """Render a simple bar chart inside a Panel using Rich."""
    if not data:
        console.print(Panel("No data to visualize", title=title))
        return
    max_value = max(data.values())
    if max_value <= 0:
        console.print(Panel("No data to visualize", title=title))
        return

    lines = []
    for label, value in sorted(data.items(), key=lambda item: item[1], reverse=True):
        bar_length = max(1, int((value / max_value) * 30))
        bar = "█" * bar_length
        lines.append(f"{label:<20} {bar} {value}")

    console.print(Panel("\n".join(lines), title=title))


def render_username_visualization(result: Dict[str, object]) -> None:
    platforms = result.get("platforms", [])
    counts = Counter("Available" if p.get("exists") else "Unavailable" for p in platforms)
    render_bar_panel(counts, "Username Availability")


def render_name_visualization(records: List[Dict[str, Optional[str]]]) -> None:
    age_counter: Counter = Counter()
    state_counter: Counter = Counter()
    for entry in records:
        age = entry.get("age")
        if age and age.isdigit():
            decade = f"{(int(age) // 10) * 10}s"
            age_counter[decade] += 1
        else:
            age_counter["Unknown"] += 1

        location = entry.get("location") or "Unknown"
        state = location.split(",")[-1].strip()
        state_counter[state or "Unknown"] += 1

    render_bar_panel(age_counter, "Age Distribution")
    render_bar_panel(state_counter, "Locations by State/Region")


def render_ip_visualization(ip_data: Dict[str, str]) -> None:
    details = [
        f"IP: {ip_data.get('ip', 'N/A')}",
        f"ISP: {ip_data.get('isp', 'N/A')}",
        f"Location: {ip_data.get('location', 'N/A')}",
    ]
    if ip_data.get("org"):
        details.append(f"Organization: {ip_data['org']}")
    if ip_data.get("timezone"):
        details.append(f"Timezone: {ip_data['timezone']}")
    if ip_data.get("network_type"):
        details.append(f"Type: {ip_data['network_type']}")
    if ip_data.get("secondary_source"):
        details.append(f"Secondary Source: {ip_data['secondary_source']}")

    console.print(Panel("\n".join(details), title="IP Insight"))


def write_result_file(prefix: str, identifier: str, lines: List[str]) -> str:
    slug = safe_slug(identifier) or "result"
    base_prefix = FILENAME_PREFIXES.get(prefix, f"{prefix}_")
    base_name = f"{base_prefix}{slug}"
    filename = Path(f"{base_name}.txt")
    counter = 0
    while filename.exists():
        counter += 1
        filename = Path(f"{base_name}{counter}.txt")
    filename.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return filename.name

def search_name(name: str):
    token = os.getenv("SCRAPE_API_KEY")
    if not token:
        console.print("[red]Error: SCRAPE_API_KEY environment variable not set[/red]")
        return []

    normalized_name = " ".join(name.split())
    if not normalized_name:
        console.print("[red]Error: Name query must contain at least one character[/red]")
        return []

    normalized_target = normalize_person_name(normalized_name)
    path_segment = quote(normalized_name.replace(" ", "-"), safe="-")
    target_url = f"https://www.fastpeoplesearch.com/name/{path_segment}"
    api_url = f"https://api.scrape.do/?{urlencode({'token': token, 'url': target_url})}"

    try:
        response = rate_limited_request("GET", api_url, timeout=45)
        response.raise_for_status()
    except requests.RequestException as exc:
        console.print(f"[red]Error fetching data: {exc}[/red]")
        return []

    soup = BeautifulSoup(response.text, "html.parser")
    records: List[PersonRecord] = []
    seen = set()

    for node in iter_person_nodes(soup):
        record = build_person_record(node, normalized_target)
        if not record or record.score <= 0:
            continue
        key = (record.url, record.name, record.location)
        if key in seen:
            continue
        seen.add(key)
        records.append(record)

    if not records:
        return []

    records.sort(key=lambda rec: (-rec.score, rec.name.lower()))
    return [rec.to_dict() for rec in records]

@app.command()
def main(
    ctx: typer.Context,
    n: Optional[str] = typer.Option(None, "-n", "--name", help="Performs a name search."),
    un: Optional[str] = typer.Option(None, "-un", "--username", help="Performs a username search."),
    ip: Optional[str] = typer.Option(None, "-ip", "--ip-address", help="Performs an IP search."),
    delay: float = typer.Option(0.25, "--delay", help="Delay between platform requests for username searches."),
    visualize: bool = typer.Option(False, "--visualize", help="Render simple visualizations of the results."),
):
    tasks = []
    if un:
        tasks.append(("username", un))
    if ip:
        tasks.append(("ip", ip))
    if n:
        tasks.append(("name", n))

    if not tasks:
        console.print("[yellow]Nothing to do — specify one of the options below.[/yellow]")
        typer.echo(ctx.get_help())
        raise typer.Exit(code=2)

    multiple = len(tasks) > 1
    combined_lines: List[str] = []
    identifier_values: Dict[str, str] = {}
    labels = {
        "username": "Username Search",
        "ip": "IP Lookup",
        "name": "Name Search",
    }

    for index, (task_type, value) in enumerate(tasks, start=1):
        label = labels[task_type]
        if multiple:
            console.print()
            console.print(f"[green]=== {label} ({index}/{len(tasks)}) ===[/green]")

        if task_type == "name":
            identifier_values["name"] = value
            results = search_name(value)
            lines: List[str] = []
            section_title = f"=== {label}: {value} ==="

            if results:
                table = Table(title=f"Name Search Results: {value}")
                table.add_column("Name")
                table.add_column("Age")
                table.add_column("Location")
                table.add_column("Phone")
                table.add_column("Profile URL")

                for entry in results:
                    table.add_row(
                        entry.get("name") or "N/A",
                        entry.get("age") or "N/A",
                        entry.get("location") or "N/A",
                        entry.get("phone") or "N/A",
                        entry.get("url") or "N/A",
                    )
                    lines.extend([
                        f"Name: {entry.get('name') or 'N/A'}",
                        f"Age: {entry.get('age') or 'N/A'}",
                        f"Location: {entry.get('location') or 'N/A'}",
                        f"Phone: {entry.get('phone') or 'N/A'}",
                        f"Profile URL: {entry.get('url') or 'N/A'}",
                        "-" * 50,
                    ])

                console.print(table)
                if visualize:
                    render_name_visualization(results)
            else:
                console.print(f"[red]No matches found for: {value}[/red]")
                lines = [f"No matches found for: {value}"]

            if multiple:
                combined_lines.append(section_title)
                combined_lines.extend(lines)
                combined_lines.append("")
            else:
                filename = write_result_file("name", value, lines)
                console.print(f"[green]Results written to file: {filename}[/green]")
            continue

        if task_type == "ip":
            try:
                result = lookup_ip(value)
            except ValueError as exc:
                console.print(f"[red]{exc}[/red]")
                if not multiple:
                    typer.echo(ctx.get_help())
                    raise typer.Exit(code=2)
                continue

            identifier_values["ip"] = result["ip"]
            lines = [
                f"IP: {result['ip']}",
                f"ISP: {result['isp']}",
                f"Location: {result['location']}",
            ]
            if result.get("org"):
                lines.append(f"Organization: {result['org']}")
            if result.get("timezone"):
                lines.append(f"Timezone: {result['timezone']}")
            if result.get("network_type"):
                lines.append(f"Type: {result['network_type']}")
            if result.get("secondary_source"):
                lines.append(f"Secondary Source: {result['secondary_source']}")

            for line in lines:
                console.print(line)
            if visualize:
                render_ip_visualization(result)
            section_title = f"=== {label}: {value} ==="
            if multiple:
                combined_lines.append(section_title)
                combined_lines.extend(lines)
                combined_lines.append("")
            else:
                filename = write_result_file("ip", result["ip"], lines)
                console.print(f"[green]Results written to file: {filename}[/green]")
            continue

        username = value.lstrip("@")
        res = check_username(username, delay=delay)
        console.print(table_for_username(res))
        text_lines: List[str] = []
        for platform in res["platforms"]:
            line = f"{platform['name']}: {'yes' if platform['exists'] else 'no'}  ({platform['status']}) - {platform['url']}"
            console.print(line)
            text_lines.append(line)
        if visualize:
            render_username_visualization(res)
        identifier_values["username"] = res["input"]
        section_title = f"=== {label}: {value} ==="
        if multiple:
            combined_lines.append(section_title)
            combined_lines.extend(text_lines)
            combined_lines.append("")
        else:
            filename = write_result_file("un", res["input"], text_lines)
            console.print(f"[green]Results written to file: {filename}[/green]")

    if multiple and combined_lines:
        prefix_order = [("ip", "ip"), ("name", "n"), ("username", "un")]
        prefix_parts = [prefix for key, prefix in prefix_order if key in identifier_values]
        identifier_parts: List[str] = []
        if "name" in identifier_values and identifier_values["name"]:
            identifier_parts.append(identifier_values["name"])
        elif "username" in identifier_values and identifier_values["username"]:
            identifier_parts.append(identifier_values["username"])
        combined_prefix = "_".join(prefix_parts) if prefix_parts else "results"
        combined_identifier = "__".join(identifier_parts) if identifier_parts else "combined"
        filename = write_result_file(combined_prefix, combined_identifier, combined_lines)
        console.print(f"[green]Results written to file: {filename}[/green]")

if __name__ == "__main__":
    app()
