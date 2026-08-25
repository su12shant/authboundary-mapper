"""
Target and role configuration for the authorization boundary crawler.

Each target defines:
- base_url: root of the application
- roles: dict of role_name -> credentials + login flow selectors
- scope: list of URL path prefixes to stay within (avoid crawling out of scope)
- exclude: list of path substrings to skip (logout links, external redirects, etc.)
"""

from dataclasses import dataclass, field


@dataclass
class RoleConfig:
    name: str
    login_url: str
    username: str
    password: str
    username_selector: str = 'input[name="email"]'
    password_selector: str = 'input[name="password"]'
    submit_selector: str = 'button[type="submit"]'
    # Optional: a URL/selector that only appears once logged in successfully,
    # used to verify the login actually worked.
    post_login_indicator: str = None


@dataclass
class TargetConfig:
    name: str
    base_url: str
    roles: list  # list[RoleConfig]
    scope_prefixes: list = field(default_factory=list)
    exclude_substrings: list = field(default_factory=lambda: ["logout", "signout"])
    max_pages_per_role: int = 150
    request_delay_ms: int = 250  # be polite, avoid hammering the target


# ---------------------------------------------------------------------------
# Example target: OWASP crAPI (Completely Ridiculous API) — designed for
# exactly this kind of BOLA/IDOR testing. Good primary validation target.
# https://github.com/OWASP/crAPI
# ---------------------------------------------------------------------------
CRAPI_TARGET = TargetConfig(
    name="crapi",
    base_url="http://localhost:8888",
    roles=[
        RoleConfig(
            name="victim",
            login_url="http://localhost:8888/login",
            username="victim@example.com",
            password="ChangeMe123!",
            post_login_indicator="/dashboard",
        ),
        RoleConfig(
            name="attacker",
            login_url="http://localhost:8888/login",
            username="attacker@example.com",
            password="ChangeMe123!",
            post_login_indicator="/dashboard",
        ),
    ],
    scope_prefixes=["http://localhost:8888"],
)

# ---------------------------------------------------------------------------
# Example target: OWASP Juice Shop
# ---------------------------------------------------------------------------
JUICESHOP_TARGET = TargetConfig(
    name="juiceshop",
    base_url="http://localhost:3000",
    roles=[
        RoleConfig(
            name="victim",
            login_url="http://localhost:3000/#/login",
            username="victim@juice-sh.op",
            password="password123",
            username_selector="#email",
            password_selector="#password",
            submit_selector="#loginButton",
        ),
        RoleConfig(
            name="attacker",
            login_url="http://localhost:3000/#/login",
            username="attacker@juice-sh.op",
            password="password123",
            username_selector="#email",
            password_selector="#password",
            submit_selector="#loginButton",
        ),
    ],
    scope_prefixes=["http://localhost:3000"],
)

TARGETS = {
    "crapi": CRAPI_TARGET,
    "juiceshop": JUICESHOP_TARGET,
}
