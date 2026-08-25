"""
Interactive terminal interface for the Authorization Boundary Mapper.

Run this instead of main.py when you don't want to hand-edit config.py
every time. It prompts you for the target URL, roles, and credentials,
builds the config in memory, runs the full pipeline, and prints a
readable summary of findings straight to the terminal.

Usage:
    python3 interactive.py
"""

import sys
from playwright.sync_api import sync_playwright

from config import TargetConfig, RoleConfig
from models import AccessMatrix
from auth import login_and_get_context
from crawler import RoleCrawler
from diff_engine import find_csrf_gaps, replay_cross_role, save_findings

try:
    from rich.console import Console
    from rich.table import Table
    from rich.prompt import Prompt, Confirm
    RICH = True
    console = Console()
except ImportError:
    RICH = False


def ask(prompt, default=None):
    if RICH:
        return Prompt.ask(prompt, default=default)
    suffix = f" [{default}]" if default else ""
    val = input(f"{prompt}{suffix}: ").strip()
    return val or default


def confirm(prompt, default=True):
    if RICH:
        return Confirm.ask(prompt, default=default)
    val = input(f"{prompt} [{'Y/n' if default else 'y/N'}]: ").strip().lower()
    if not val:
        return default
    return val.startswith("y")


def say(msg, style=None):
    if RICH:
        console.print(msg, style=style)
    else:
        print(msg)


def collect_role(role_number, login_url_default):
    say(f"\n--- Role {role_number} ---", style="bold cyan" if RICH else None)
    name = ask(f"Role name (e.g. victim/attacker)", default=f"role{role_number}")
    login_url = ask("Login page URL", default=login_url_default)
    username = ask("Username / email")
    password = ask("Password")

    say("Login form field selectors (press Enter to accept common defaults):")
    username_selector = ask("  Username/email field CSS selector", default='input[name="email"]')
    password_selector = ask("  Password field CSS selector", default='input[name="password"]')
    submit_selector = ask("  Submit button CSS selector", default='button[type="submit"]')
    post_login_indicator = ask(
        "  Text/path that appears in the URL only after login succeeds (optional)",
        default=""
    )

    return RoleConfig(
        name=name,
        login_url=login_url,
        username=username,
        password=password,
        username_selector=username_selector,
        password_selector=password_selector,
        submit_selector=submit_selector,
        post_login_indicator=post_login_indicator or None,
    )


def collect_target():
    say("\n=== Authorization Boundary Mapper — Interactive Setup ===\n",
        style="bold green" if RICH else None)

    target_name = ask("Give this target a short name (e.g. crapi)", default="target")
    base_url = ask("Base URL of the application", default="http://localhost:8888")
    login_url_default = ask("Login page URL", default=f"{base_url}/login")

    n_roles = int(ask("How many roles/accounts to test with (minimum 2)", default="2"))
    n_roles = max(n_roles, 2)

    roles = []
    for i in range(1, n_roles + 1):
        roles.append(collect_role(i, login_url_default))

    max_pages = int(ask("Max pages to crawl per role", default="150"))

    return TargetConfig(
        name=target_name,
        base_url=base_url,
        roles=roles,
        scope_prefixes=[base_url],
        max_pages_per_role=max_pages,
    )


def print_findings_table(findings):
    if not findings:
        say("\nNo findings to display.")
        return

    if RICH:
        table = Table(title="Findings", show_lines=True)
        table.add_column("Type", style="bold")
        table.add_column("Confidence")
        table.add_column("Method")
        table.add_column("URL", overflow="fold")
        table.add_column("Owning role")
        table.add_column("Tested role")
        table.add_column("Evidence", overflow="fold")

        for f in findings:
            style = "red" if f.finding_type == "IDOR" else "yellow"
            table.add_row(
                f.finding_type, f.confidence, f.method, f.url,
                f.owning_role, f.tested_role, f.evidence, style=style
            )
        console.print(table)
    else:
        for f in findings:
            print(f"\n[{f.finding_type}] confidence={f.confidence}")
            print(f"  {f.method} {f.url}")
            print(f"  owning_role={f.owning_role} tested_role={f.tested_role}")
            print(f"  {f.evidence}")


def main():
    target = collect_target()
    headless = not confirm("\nRun with a visible browser window (recommended first run)?", default=True)

    matrix = AccessMatrix()
    role_contexts = {}

    say(f"\n[+] Launching browser (headless={headless})...", style="cyan" if RICH else None)

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)

        for role_config in target.roles:
            say(f"[+] Logging in as: {role_config.name}", style="cyan" if RICH else None)
            try:
                context, page = login_and_get_context(p, browser, role_config, headless)
            except RuntimeError as e:
                say(f"[!] {e}", style="bold red" if RICH else None)
                continue

            role_contexts[role_config.name] = context

            say(f"[+] Crawling as: {role_config.name}", style="cyan" if RICH else None)
            crawler = RoleCrawler(role_config.name, page, target, matrix)
            n_pages = crawler.run()
            n_reqs = len(matrix.requests_by_role.get(role_config.name, []))
            say(f"    visited {n_pages} pages, captured {n_reqs} requests")

        if len(role_contexts) < 2:
            say("\n[!] Need at least 2 successfully logged-in roles to run IDOR replay. Stopping.",
                style="bold red" if RICH else None)
            browser.close()
            sys.exit(1)

        say("\n[+] Running cross-role replay for IDOR detection...", style="cyan" if RICH else None)
        idor_findings = replay_cross_role(p, target, matrix, role_contexts)
        say(f"    {len(idor_findings)} potential IDOR findings")

        say("[+] Scanning for missing CSRF tokens...", style="cyan" if RICH else None)
        csrf_findings = find_csrf_gaps(matrix)
        say(f"    {len(csrf_findings)} potential CSRF gaps")

        import os
        os.makedirs("reports", exist_ok=True)
        matrix.save(f"reports/{target.name}_access_matrix.json")
        all_findings = idor_findings + csrf_findings
        save_findings(all_findings, f"reports/{target.name}_findings.json")

        for ctx in role_contexts.values():
            ctx.close()
        browser.close()

    say(f"\n[+] Full reports saved to reports/{target.name}_access_matrix.json "
        f"and reports/{target.name}_findings.json\n", style="bold green" if RICH else None)

    print_findings_table(all_findings)


if __name__ == "__main__":
    main()
