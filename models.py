"""
Data models for captured HTTP traffic and the resulting access matrix.
"""

import re
import time
import json
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, parse_qs

STATE_CHANGING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Matches common resource-ID patterns in a URL path:
#  /api/users/42        -> numeric ID
#  /api/orders/ab12cd    -> alphanumeric/UUID-ish ID
#  /api/user/uuid-4dashes-form
ID_PATTERN = re.compile(
    r"/(?P<segment>[a-zA-Z_]+)/(?P<id>[0-9]+|[0-9a-fA-F]{8}-[0-9a-fA-F-]{27}|[0-9a-fA-F]{24})(?=/|$|\?)"
)


@dataclass
class CapturedRequest:
    role: str
    method: str
    url: str
    status: int
    path: str
    query_params: dict
    resource_ids: list          # [(segment, id), ...] extracted from path
    has_csrf_token: bool        # was an anti-CSRF token present in headers/body?
    csrf_token_value: str       # raw value if found, for predictability checks
    request_headers: dict
    response_snippet: str       # truncated body, for manual review context
    timestamp: float = field(default_factory=time.time)

    def to_dict(self):
        return asdict(self)


def extract_resource_ids(path: str):
    """Pull (resource_type, id) pairs out of a URL path."""
    return [(m.group("segment"), m.group("id")) for m in ID_PATTERN.finditer(path)]


def detect_csrf_token(headers: dict, post_data: str):
    """
    Heuristic CSRF token detection. Looks for common token header/field names.
    Returns (found: bool, value: str or None).
    """
    common_names = [
        "x-csrf-token", "x-xsrf-token", "csrf-token", "x-csrftoken",
        "csrfmiddlewaretoken", "_csrf", "authenticity_token",
    ]
    lower_headers = {k.lower(): v for k, v in headers.items()}
    for name in common_names:
        if name in lower_headers:
            return True, lower_headers[name]

    if post_data:
        for name in common_names:
            match = re.search(rf'{name}["\']?\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]+)', post_data, re.I)
            if match:
                return True, match.group(1)

    return False, None


class AccessMatrix:
    """
    Maps role -> set of (resource_type, resource_id) it successfully accessed,
    plus the full list of captured requests for replay / diffing.
    """

    def __init__(self):
        self.requests_by_role = {}   # role -> list[CapturedRequest]
        self.resources_by_role = {}  # role -> set[(resource_type, id)]

    def add(self, req: CapturedRequest):
        self.requests_by_role.setdefault(req.role, []).append(req)
        bucket = self.resources_by_role.setdefault(req.role, set())
        for rid in req.resource_ids:
            bucket.add(rid)

    def roles(self):
        return list(self.requests_by_role.keys())

    def save(self, path: str):
        out = {
            "requests_by_role": {
                role: [r.to_dict() for r in reqs]
                for role, reqs in self.requests_by_role.items()
            },
            "resources_by_role": {
                role: sorted(list(ids)) for role, ids in self.resources_by_role.items()
            },
        }
        with open(path, "w") as f:
            json.dump(out, f, indent=2, default=str)
