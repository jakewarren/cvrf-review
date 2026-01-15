#!/usr/bin/env python3
import os
import json
import datetime
import requests
import xml.etree.ElementTree as ET
import xmltodict

FEED_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"


def main():
    try:
        resp = requests.get(FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
    except (requests.RequestException, ET.ParseError) as e:
        print(f"Failed to fetch or parse feed {FEED_URL}: {e}")
        import sys

        sys.exit(1)

    failed_fetches = 0
    for item in root.findall(".//item"):
        link = item.findtext("link")
        pub_date = item.findtext("pubDate")
        if not link or not pub_date:
            continue
        try:
            year = datetime.datetime.strptime(pub_date, "%a, %d %b %Y %H:%M:%S %z").year
        except ValueError:
            year = "unknown"
        vuln_id = link.rstrip("/").split("/")[-1]
        out_dir = os.path.join("cvrf", "fortinet", str(year))
        out_path = os.path.join(out_dir, f"{vuln_id}.json")
        if os.path.exists(out_path):
            print(f"Skipping {vuln_id}, already exists")
            continue

        cvrf_url = f"https://fortiguard.fortinet.com/psirt/cvrf/{vuln_id}"
        cvrf_resp = requests.get(
            cvrf_url,
            headers={"Accept": "application/xml", "User-Agent": USER_AGENT},
            timeout=30,
        )
        if cvrf_resp.status_code != 200:
            print(f"Failed to fetch {cvrf_url}: {cvrf_resp.status_code}")
            failed_fetches += 1
            continue
        try:
            data = xmltodict.parse(cvrf_resp.text)
        except Exception as e:
            print(f"Failed to parse XML for {cvrf_url}: {e}")
            continue
        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        except OSError as e:
            print(f"Failed to write {out_path}: {e}")
            continue
        print(f"Saved {out_path}")

    if failed_fetches > 0:
        print(f"\nFailed to fetch {failed_fetches} advisory(ies). Exiting with error.")
        import sys

        sys.exit(1)


if __name__ == "__main__":
    main()
