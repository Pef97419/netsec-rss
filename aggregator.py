#!/usr/bin/env python3
import os, sys, time, json, re, math, html, hashlib, datetime
from datetime import datetime, timedelta, timezone
import xml.etree.ElementTree as ET

import requests
import yaml
import feedparser

UTC = timezone.utc

def now_utc():
    return datetime.now(UTC)

def http_get(url, timeout=30):
    headers = {"User-Agent": "netsec-rss-aggregator/1.0 (+github actions)"}
    r = requests.get(url, timeout=timeout, headers=headers)
    r.raise_for_status()
    return r

def try_parse_date(s):
    # feedparser handles dates mostly; this is a fallback
    for fmt in ("%a, %d %b %Y %H:%M:%S %Z", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).replace(tzinfo=UTC)
        except Exception:
            pass
    return None

def extract_cves(text):
    if not text:
        return set()
    return set(re.findall(r"CVE-\d{4}-\d{4,7}", text, flags=re.I))

def max_cvss_from_nvd_metrics(cve):
    score = None
    metrics = cve.get("metrics", {})
    for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
        arr = metrics.get(key, [])
        for m in arr:
            data = m.get("cvssData", {})
            bs = data.get("baseScore")
            if bs is not None:
                if score is None or bs > score:
                    score = float(bs)
    return score

def build_rss(channel_title, channel_link, channel_desc, items):
    rss = ET.Element("rss", version="2.0")
    channel = ET.SubElement(rss, "channel")
    ET.SubElement(channel, "title").text = channel_title
    ET.SubElement(channel, "link").text = channel_link
    ET.SubElement(channel, "description").text = channel_desc
    ET.SubElement(channel, "lastBuildDate").text = now_utc().strftime("%a, %d %b %Y %H:%M:%S GMT")

    for it in items:
        item = ET.SubElement(channel, "item")
        ET.SubElement(item, "title").text = it["title"]
        ET.SubElement(item, "link").text = it["link"]
        ET.SubElement(item, "guid").text = it.get("guid", it["link"])
        ET.SubElement(item, "pubDate").text = it["pubDate"].strftime("%a, %d %b %Y %H:%M:%S GMT")
        ET.SubElement(item, "description").text = it["description"]
    return ET.tostring(rss, encoding="utf-8", xml_declaration=True)

def load_config():
    with open("config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def fetch_vendor_feeds(vendors):
    items = []
    for v in vendors:
        url = v["url"]
        title = v["title"]
        try:
            d = feedparser.parse(url)
            for e in d.entries:
                link = e.get("link") or url
                pub = None
                if hasattr(e, "published_parsed") and e.published_parsed:
                    pub = datetime.fromtimestamp(time.mktime(e.published_parsed), tz=UTC)
                elif hasattr(e, "updated_parsed") and e.updated_parsed:
                    pub = datetime.fromtimestamp(time.mktime(e.updated_parsed), tz=UTC)
                else:
                    pub = now_utc()

                summary = e.get("summary", "")
                cves = extract_cves(e.get("title", "") + " " + summary)
                title_e = e.get("title") or f"{title} advisory"
                if cves:
                    title_e = f"{title_e} ({', '.join(sorted(cves))})"

                items.append({
                    "title": title_e,
                    "link": link,
                    "guid": e.get("id", link),
                    "pubDate": pub,
                    "description": f"{title} – {summary}",
                    "source": title,
                    "cves": list(cves),
                    "cvss": None
                })
        except Exception as ex:
            print(f"[WARN] Vendor feed failed: {title} – {url} – {ex}", file=sys.stderr)
    return items

def fetch_cisa_kev():
    items = []
    try:
        # KEV JSON
        kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        data = http_get(kev_url).json()
        for v in data.get("vulnerabilities", []):
            cve = v.get("cveID")
            name = v.get("vendorProject", "") + " " + v.get("product", "")
            date_added = v.get("dateAdded")
            try:
                pub = datetime.strptime(date_added, "%Y-%m-%d").replace(tzinfo=UTC)
            except Exception:
                pub = now_utc()
            title = f"KEV: {cve} exploited – {name}".strip()
            desc = f"{v.get('shortDescription','')} | Required Action by {v.get('requiredAction','N/A')} | Due {v.get('dueDate','N/A')}"
            link = v.get("notes", "") or "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
            items.append({
                "title": title,
                "link": link,
                "guid": f"kev-{cve}",
                "pubDate": pub,
                "description": desc,
                "source": "CISA KEV",
                "cves": [cve] if cve else [],
                "cvss": None
            })
    except Exception as ex:
        print(f"[WARN] CISA KEV fetch failed: {ex}", file=sys.stderr)
    return items

def fetch_nvd(keywords, days_back, cvss_min):
    items = []
    base = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    start = (now_utc() - timedelta(days=days_back)).strftime("%Y-%m-%dT%H:%M:%S.000") + " UTC+00:00"
    params_common = {
        "pubStartDate": start,
        "resultsPerPage": 200,
    }

    queries = keywords or []
    if not queries:
        queries = ["network", "router", "switch"]

    for q in queries:
        params = dict(params_common)
        params["keywordSearch"] = q
        try:
            r = requests.get(base, params=params, timeout=60, headers={"User-Agent":"netsec-rss-aggregator/1.0"})
            r.raise_for_status()
            data = r.json()
            for cve in data.get("vulnerabilities", []):
                cve_obj = cve.get("cve", {})
                cve_id = cve_obj.get("id")
                score = max_cvss_from_nvd_metrics(cve_obj)
                if score is None or (cvss_min and score < cvss_min):
                    continue
                descs = cve_obj.get("descriptions", [])
                desc = next((d.get("value") for d in descs if d.get("lang") == "en"), "") or (descs[0].get("value") if descs else "")
                pub = cve_obj.get("published")
                try:
                    pub_dt = datetime.strptime(pub, "%Y-%m-%dT%H:%M:%S.%f").replace(tzinfo=UTC) if pub else now_utc()
                except Exception:
                    pub_dt = now_utc()
                url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                title = f"{cve_id} (CVSS {score}) – {q}"
                items.append({
                    "title": title,
                    "link": url,
                    "guid": f"nvd-{cve_id}",
                    "pubDate": pub_dt,
                    "description": desc[:1000],
                    "source": f"NVD:{q}",
                    "cves": [cve_id],
                    "cvss": score
                })
        except Exception as ex:
            print(f"[WARN] NVD fetch failed for '{q}': {ex}", file=sys.stderr)
    return items

def dedupe_items(items):
    seen = set()
    out = []
    for it in sorted(items, key=lambda x: x["pubDate"], reverse=True):
        key = None
        if it["cves"]:
            key = tuple(sorted(it["cves"]))
        else:
            key = it["guid"]
        if key in seen:
            continue
        seen.add(key)
        out.append(it)
    return out

def main():
    cfg = load_config()
    cvss_min = float(cfg.get("cvss_min", 7.0))
    vendors = cfg.get("vendors", [])
    keywords = cfg.get("keywords", [])
    days = int(cfg.get("nvd_days_back", 14))

    items = []
    items += fetch_vendor_feeds(vendors)
    items += fetch_cisa_kev()
    items += fetch_nvd(keywords, days, cvss_min)

    items = dedupe_items(items)

    os.makedirs("docs", exist_ok=True)
    rss_bytes = build_rss(
        channel_title="Network Security Unified Feed",
        channel_link="https://example.com",
        channel_desc=f"Aggregated advisories + CVEs (CVSS ≥ {cvss_min}) – generated {now_utc().isoformat()}",
        items=items[:500]
    )
    with open("docs/feed.xml", "wb") as f:
        f.write(rss_bytes)
    # simple index
    with open("docs/index.html", "w", encoding="utf-8") as f:
        f.write('<!doctype html><meta charset="utf-8"><title>Network Security RSS</title><h1>Network Security RSS</h1><p><a href="feed.xml">RSS feed</a></p>')
    print(f"Built {len(items)} items.")

if __name__ == "__main__":
    main()
