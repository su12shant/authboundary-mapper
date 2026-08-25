"""
This is the actual detection logic — the part that matters most in your
report, so it's worth understanding exactly what it does:

1. IDOR / Broken Object-Level Authorization detection via cross-role replay:
   For every request Role A made that returned a successful status (2xx) and
   touched a specific resource ID, replay that EXACT request (same method,
   path, params) but using Role B's authentication (cookies/tokens) instead.
   If Role B also gets a successful response to a resource that only Role A
   should own, that's a strong IDOR signal — this is real differential
   testing, not guessing at IDs.

2. CSRF gap detection:
   Flag every state-changing request (POST/PUT/PATCH/DELETE) that had no
   anti-CSRF token detected. This mirrors exactly how the Agora and Tilda
   CSRF findings were manually confirmed — missing/absent token on a
   state-changing endpoint.

Both checks produce a list of Finding objects with a confidence score so a
human reviewer (you, in the report) can prioritize what to manually verify
first — the tool's job is to narrow the haystack, not replace judgment.
"""

from dataclasses import dataclass, asdict
import json


@dataclass
class Finding:
    finding_type: str      # "IDOR" or "CSRF_MISSING_TOKEN"
    confidence: str        # "high" | "medium" | "low"
    method: str
    url: str
    owning_role: str       # role the resource appears to belong to
    tested_role: str       # role used in the replay (for IDOR)
    resource: str          # "segment/id"
    evidence: str          # short human-readable explanation

    def to_dict(self):
        return asdict(self)


def find_csrf_gaps(matrix):
    findings = []
    for role, requests in matrix.requests_by_role.items():
        for req in requests:
            if req.method in {"POST", "PUT", "PATCH", "DELETE"} and not req.has_csrf_token:
                findings.append(Finding(
                    finding_type="CSRF_MISSING_TOKEN",
                    confidence="medium",
                    method=req.method,
                    url=req.url,
                    owning_role=role,
                    tested_role=role,
                    resource="",
                    evidence=(
                        f"State-changing {req.method} request to {req.path} had no "
                        f"anti-CSRF token in headers or body. Verify manually — "
                        f"check if the endpoint is actually state-changing and "
                        f"whether SameSite cookie policy mitigates this."
                    ),
                ))
    return findings


def replay_cross_role(playwright, target_config, matrix, role_contexts):
    """
    role_contexts: dict of role_name -> Playwright BrowserContext (still logged in)

    For every resource Role A touched successfully, replay the same request
    using every OTHER role's context and record whether it also succeeds.
    """
    findings = []
    roles = matrix.roles()

    for owning_role in roles:
        for req in matrix.requests_by_role[owning_role]:
            if req.status < 200 or req.status >= 300:
                continue
            if not req.resource_ids:
                continue

            for other_role in roles:
                if other_role == owning_role:
                    continue
                if other_role not in role_contexts:
                    continue

                context = role_contexts[other_role]
                api_request = context.request

                try:
                    resp = api_request.fetch(
                        req.url,
                        method=req.method,
                        headers={k: v for k, v in req.request_headers.items()
                                 if k.lower() not in ("host", "content-length")},
                    )
                    if 200 <= resp.status < 300:
                        segment, rid = req.resource_ids[0]
                        findings.append(Finding(
                            finding_type="IDOR",
                            confidence="high",
                            method=req.method,
                            url=req.url,
                            owning_role=owning_role,
                            tested_role=other_role,
                            resource=f"{segment}/{rid}",
                            evidence=(
                                f"Resource {segment}/{rid}, originally accessed by "
                                f"'{owning_role}', was also successfully accessed "
                                f"(status {resp.status}) using '{other_role}' credentials. "
                                f"Manually verify this is a genuine cross-account access, "
                                f"not a shared/public resource."
                            ),
                        ))
                except Exception:
                    continue  # network/replay error, skip this pair

    return findings


def save_findings(findings, path):
    with open(path, "w") as f:
        json.dump([f.to_dict() for f in findings], f, indent=2)
