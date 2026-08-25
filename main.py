"""
Entrypoint: run the full authorization-boundary testing pipeline against a target.

Usage:
    python main.py --target crapi
    python main.py --target juiceshop --headless false

Pipeline:
    1. Launch browser, log in as every configured role
    2. Crawl the app as each role, capturing all network traffic
    3. Cross-role replay to detect IDOR
    4. Scan captured state-changing requests for missing CSRF tokens
    5. Write access_matrix.json and findings.json to reports/
"""

import argparse
import sys
from playwright.sync_api import sync_playwright

from core.config import TARGETS
from core.models import AccessMatrix
from core.auth import login_and_get_context
from core.crawler import RoleCrawler
from core.diff_engine import find_csrf_gaps, replay_cross_role, save_findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, choices=list(TARGETS.keys()))
    parser.add_argument("--headless", default="true")
    args = parser.parse_args()

    headless = args.headless.lower() != "false"
    target = TARGETS[args.target]
    matrix = AccessMatrix()
    role_contexts = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)

        # --- Step 1 & 2: log in and crawl as each role ---
        for role_config in target.roles:
            print(f"[+] Logging in as role: {role_config.name}")
            try:
                context, page = login_and_get_context(p, browser, role_config, headless)
            except RuntimeError as e:
                print(f"[!] {e}")
                continue

            role_contexts[role_config.name] = context

            print(f"[+] Crawling as: {role_config.name}")
            crawler = RoleCrawler(role_config.name, page, target, matrix)
            n_pages = crawler.run()
            n_reqs = len(matrix.requests_by_role.get(role_config.name, []))
            print(f"    visited {n_pages} pages, captured {n_reqs} requests")

        # --- Step 3: cross-role IDOR replay ---
        print("[+] Running cross-role replay for IDOR detection...")
        idor_findings = replay_cross_role(p, target, matrix, role_contexts)
        print(f"    {len(idor_findings)} potential IDOR findings")

        # --- Step 4: CSRF gap scan ---
        print("[+] Scanning for missing CSRF tokens...")
        csrf_findings = find_csrf_gaps(matrix)
        print(f"    {len(csrf_findings)} potential CSRF gaps")

        # --- Step 5: write reports ---
        matrix.save(f"reports/{target.name}_access_matrix.json")
        all_findings = idor_findings + csrf_findings
        save_findings(all_findings, f"reports/{target.name}_findings.json")
        print(f"[+] Reports written to reports/{target.name}_access_matrix.json "
              f"and reports/{target.name}_findings.json")

        for ctx in role_contexts.values():
            ctx.close()
        browser.close()


if __name__ == "__main__":
    main()
