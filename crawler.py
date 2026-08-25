"""
Strong authenticated crawler.

For a given logged-in role:
  1. BFS-walks the app's discoverable pages (links + form actions), staying
     in scope.
  2. Intercepts EVERY network response (XHR/fetch/document) via Playwright's
     response event — this is what makes it "strong": it doesn't just look
     at rendered HTML, it captures the actual API traffic the SPA makes,
     which is where the real IDOR/CSRF-relevant endpoints live.
  3. For each response, extracts resource IDs from the URL, checks for CSRF
     tokens on state-changing requests, and stores a CapturedRequest.

This deliberately avoids headless "requests"-library crawling because modern
SPAs (React/Vue/Angular — crAPI and Juice Shop both are) don't expose most
of their real endpoints in static HTML. You need a real browser driving it.
"""

import time
from collections import deque
from urllib.parse import urljoin, urlparse

from core.models import CapturedRequest, extract_resource_ids, detect_csrf_token, STATE_CHANGING_METHODS


class RoleCrawler:
    def __init__(self, role_name, page, target_config, access_matrix):
        self.role_name = role_name
        self.page = page
        self.target = target_config
        self.matrix = access_matrix
        self.visited = set()
        self.queue = deque([target_config.base_url])
        self._captured_this_page = []

        # Hook into every network response for this page/context.
        self.page.on("response", self._on_response)

    def _in_scope(self, url):
        if self.target.scope_prefixes and not any(
            url.startswith(p) for p in self.target.scope_prefixes
        ):
            return False
        if any(ex in url for ex in self.target.exclude_substrings):
            return False
        return True

    def _on_response(self, response):
        try:
            request = response.request
            url = response.url
            method = request.method
            path = urlparse(url).path
            query_params = dict(
                pair.split("=", 1) if "=" in pair else (pair, "")
                for pair in (urlparse(url).query.split("&") if urlparse(url).query else [])
            )
            resource_ids = extract_resource_ids(path)

            headers = request.headers
            post_data = request.post_data or ""
            has_csrf, csrf_val = detect_csrf_token(headers, post_data)

            body_snippet = ""
            try:
                if "application/json" in (response.headers.get("content-type", "")):
                    body_snippet = response.text()[:500]
            except Exception:
                pass  # binary/streaming responses, or already consumed

            captured = CapturedRequest(
                role=self.role_name,
                method=method,
                url=url,
                status=response.status,
                path=path,
                query_params=query_params,
                resource_ids=resource_ids,
                has_csrf_token=has_csrf,
                csrf_token_value=csrf_val,
                request_headers=dict(headers),
                response_snippet=body_snippet,
            )
            self.matrix.add(captured)
        except Exception:
            # Never let a single malformed response kill the crawl.
            pass

    def _discover_links(self):
        """Pull hrefs and form actions off the current page for BFS expansion."""
        links = set()
        try:
            hrefs = self.page.eval_on_selector_all(
                "a[href]", "els => els.map(e => e.href)"
            )
            links.update(hrefs)
        except Exception:
            pass
        try:
            form_actions = self.page.eval_on_selector_all(
                "form[action]", "els => els.map(e => e.action)"
            )
            links.update(form_actions)
        except Exception:
            pass
        return links

    def run(self):
        pages_visited = 0
        while self.queue and pages_visited < self.target.max_pages_per_role:
            url = self.queue.popleft()
            if url in self.visited or not self._in_scope(url):
                continue

            self.visited.add(url)
            try:
                self.page.goto(url, wait_until="networkidle", timeout=15000)
            except Exception:
                continue

            pages_visited += 1
            time.sleep(self.target.request_delay_ms / 1000)

            for link in self._discover_links():
                if link not in self.visited:
                    self.queue.append(link)

        return pages_visited
