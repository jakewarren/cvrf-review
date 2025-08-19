#!/usr/bin/env python3
import os
import json
import datetime
import requests
import xml.etree.ElementTree as ET
import xmltodict

FEED_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"


def main():
    resp = requests.get(FEED_URL, timeout=30)
    resp.raise_for_status()
    root = ET.fromstring(resp.content)

    for item in root.findall('.//item'):
        link = item.findtext('link')
        pub_date = item.findtext('pubDate')
        if not link or not pub_date:
            continue
        try:
            year = datetime.datetime.strptime(pub_date, "%a, %d %b %Y %H:%M:%S %z").year
        except ValueError:
            year = "unknown"
        vuln_id = link.rstrip('/').split('/')[-1]
        out_dir = os.path.join("cvrf", str(year))
        out_path = os.path.join(out_dir, f"{vuln_id}.json")
        if os.path.exists(out_path):
            print(f"Skipping {vuln_id}, already exists")
            continue

        cvrf_url = f"https://fortiguard.fortinet.com/psirt/cvrf/{vuln_id}"
        cvrf_resp = requests.get(cvrf_url, timeout=30)
        if cvrf_resp.status_code != 200:
            print(f"Failed to fetch {cvrf_url}: {cvrf_resp.status_code}")
            continue
        data = xmltodict.parse(cvrf_resp.content)
        os.makedirs(out_dir, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Saved {out_path}")


if __name__ == "__main__":
    main()
