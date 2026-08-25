"""
Handles logging in as a given role and returning an authenticated
Playwright BrowserContext (with cookies/localStorage already set),
so the crawler can just start browsing.
"""

from playwright.sync_api import sync_playwright


def login_and_get_context(playwright, browser, role_config, headless=True):
    """
    Logs in as `role_config` and returns (context, page) already authenticated.
    Raises RuntimeError if the post-login indicator never appears (login failed).
    """
    context = browser.new_context()
    page = context.new_page()

    page.goto(role_config.login_url, wait_until="networkidle")

    page.fill(role_config.username_selector, role_config.username)
    page.fill(role_config.password_selector, role_config.password)

    with page.expect_navigation(wait_until="networkidle", timeout=15000):
        page.click(role_config.submit_selector)

    if role_config.post_login_indicator:
        try:
            page.wait_for_url(f"**{role_config.post_login_indicator}**", timeout=10000)
        except Exception:
            # SPA apps often don't change the actual URL — fall back to checking
            # whether the login form disappeared, which is a decent proxy signal.
            still_on_login = page.query_selector(role_config.username_selector)
            if still_on_login:
                raise RuntimeError(
                    f"Login appears to have failed for role '{role_config.name}'. "
                    f"Login form still present after submit."
                )

    return context, page
