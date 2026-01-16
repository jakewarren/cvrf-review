#!/usr/bin/env python3
import os
import json
import datetime
import time
import requests
import xml.etree.ElementTree as ET
import xmltodict

FEED_URL = "https://filestore.fortinet.com/fortiguard/rss/ir.xml"
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
SLEEP_SECONDS = 30  # Sleep between CVRF requests to avoid rate limiting


def main():
    try:
        resp = requests.get(FEED_URL, headers={"User-Agent": USER_AGENT}, timeout=30)
        resp.raise_for_status()
        root = ET.fromstring(resp.content)
    except requests.exceptions.Timeout:
        print(f"Error: RSS feed request timed out after 30 seconds")
        import sys

        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"Error: Failed to connect to RSS feed: Connection error")
        import sys

        sys.exit(1)
    except requests.exceptions.HTTPError as e:
        print(f"Error: RSS feed request failed with HTTP {e.response.status_code}")
        import sys

        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Error: Failed to fetch RSS feed: {type(e).__name__}")
        import sys

        sys.exit(1)
    except ET.ParseError as e:
        print(f"Error: Failed to parse RSS feed XML: {e}")
        import sys

        sys.exit(1)

    failed_advisories = []
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
        try:
            cvrf_resp = requests.get(
                cvrf_url,
                headers={"Accept": "application/xml", "User-Agent": USER_AGENT},
                timeout=30,
            )
            if cvrf_resp.status_code != 200:
                print(f"Error: Failed to fetch {vuln_id}: HTTP {cvrf_resp.status_code}")
                failed_advisories.append((vuln_id, f"HTTP {cvrf_resp.status_code}"))
                time.sleep(SLEEP_SECONDS)
                continue
        except requests.exceptions.Timeout:
            print(f"Error: Request timed out for {vuln_id}")
            failed_advisories.append((vuln_id, "Request timeout"))
            time.sleep(SLEEP_SECONDS)
            continue
        except requests.exceptions.ConnectionError:
            print(f"Error: Connection failed for {vuln_id}")
            failed_advisories.append((vuln_id, "Connection error"))
            time.sleep(SLEEP_SECONDS)
            continue
        except requests.exceptions.RequestException as e:
            print(f"Error: Failed to fetch {vuln_id}: {type(e).__name__}")
            failed_advisories.append((vuln_id, type(e).__name__))
            time.sleep(SLEEP_SECONDS)
            continue
        try:
            data = xmltodict.parse(cvrf_resp.text)
        except ET.ParseError as e:
            print(f"Error: XML parse error for {vuln_id}: Malformed XML")
            failed_advisories.append((vuln_id, "XML parse error"))
            time.sleep(SLEEP_SECONDS)
            continue
        except Exception as e:
            print(f"Error: Failed to parse {vuln_id}: {type(e).__name__}")
            failed_advisories.append((vuln_id, f"Parse error: {type(e).__name__}"))
            time.sleep(SLEEP_SECONDS)
            continue
        os.makedirs(out_dir, exist_ok=True)
        try:
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        except OSError as e:
            print(f"Failed to write {out_path}: {e}")
            continue
        print(f"Saved {out_path}")
        time.sleep(SLEEP_SECONDS)  # Rate limiting: sleep after CVRF request

    if failed_advisories:
        print(f"\nFailed to process {len(failed_advisories)} advisory(ies):")
        for vuln_id, reason in failed_advisories:
            print(f"::error::Failed to process {vuln_id}: {reason}")
        print(
            f"\nNote: {len(failed_advisories)} advisory(ies) failed but workflow will continue"
        )


if __name__ == "__main__":
    main()
