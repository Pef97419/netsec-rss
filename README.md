# Network Security Unified RSS

This repo builds a **single RSS feed** aggregating:
- Vendor advisories: Cisco, Fortinet, Sophos, Palo Alto Networks, Juniper (RSS)
- Aggregators: **NVD** (CVE API v2), **CISA KEV** (Known Exploited Vulnerabilities)
- Optional keywords: **Asterfusion**, **AsterNOS**, **SONiC**, **Aruba** (via NVD)
- (You can add more in `config.yaml`)

The output is `docs/feed.xml` (RSS 2.0). Host it with **GitHub Pages**.

---

## Quick start

1. **Create a new GitHub repo** (e.g., `netsec-rss`), empty.
2. Download this project ZIP, unzip, then push everything to your repo.
3. In GitHub: **Settings → Pages → Build and deployment → Source: "Deploy from a branch"**  
   Branch: `main` · Folder: `/docs` → **Save**.
4. Wait ~1–2 minutes for the workflow to run.  
   Your feed will be at: `https://<your-username>.github.io/<your-repo>/feed.xml`

---

## Configuration

Edit `config.yaml`:

- `cvss_min`: minimum CVSS (default **7.0**).
- `keywords`: applied to **NVD** query (ANDed with CVE data) — e.g. `["Asterfusion", "AsterNOS", "SONiC", "ArubaOS"]`.
- `vendors`: list of vendor RSS feeds (title + url). Add/remove as you like.
- `nvd_days_back`: how many days of CVEs to fetch from NVD (default **14**).

Then push — the workflow will rebuild the feed.

---

## Notes

- Some vendors don't expose stable RSS. In those cases, rely on **NVD** + **CISA KEV**.
- All items are **deduplicated by CVE ID** when possible.
- The workflow runs **daily** at 06:00 UTC and also on every push.
