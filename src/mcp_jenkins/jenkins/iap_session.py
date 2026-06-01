import re
from urllib.parse import urlparse

import browser_cookie3
import requests
from loguru import logger

_MASK_RE = re.compile(r'(=[^;]{8})[^;]*')


def _mask_cookie_header(header: str) -> str:
    """Show first 8 chars of each cookie value, mask the rest."""
    return _MASK_RE.sub(r'\1…', header)


class IAPSession(requests.Session):
    """A requests.Session that injects live IAP cookies from Chrome on every request.

    Reads cookies fresh from the local Chrome cookie store per-request so that
    IAP session refreshes mid-run are picked up automatically.
    """

    def __init__(self, iap_domain: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._iap_domain = iap_domain
        logger.info(f'IAPSession initialised for domain: {iap_domain}')

    def request(self, method, url, **kwargs):
        domain = urlparse(url).hostname or self._iap_domain
        try:
            cj = browser_cookie3.chrome(domain_name=f'.{domain}')
            all_cookies = {c.name: c.value for c in cj}
            iap_cookies = {k: v for k, v in all_cookies.items() if 'IAP' in k.upper()}
            logger.debug(
                f'Chrome cookie lookup for .{domain}: '
                f'{len(all_cookies)} total cookie(s), '
                f'{len(iap_cookies)} IAP cookie(s), '
                f'IAP cookie names: {list(iap_cookies.keys()) or "(none)"}'
            )
        except Exception as exc:
            logger.warning(f'Failed to read Chrome cookies for {domain}: {exc!r}')
            iap_cookies = {}

        if iap_cookies:
            existing = kwargs.get('headers') or {}
            parts = [f'{name}={value}' for name, value in iap_cookies.items()]
            if 'Cookie' in existing:
                parts.insert(0, existing['Cookie'])
            existing['Cookie'] = '; '.join(parts)
            kwargs['headers'] = existing
        else:
            logger.warning(f'No IAP cookies found for {domain} — request will be sent without IAP cookie')

        response = super().request(method, url, **kwargs)

        # Log the request headers that were actually sent (with cookie values masked)
        sent_headers = dict(response.request.headers)
        if 'Cookie' in sent_headers:
            sent_headers['Cookie'] = _mask_cookie_header(sent_headers['Cookie'])
        if 'Authorization' in sent_headers:
            sent_headers['Authorization'] = sent_headers['Authorization'][:12] + '…'
        logger.debug(
            f'[{method}] {url} → {response.status_code} | '
            f'Request headers: {sent_headers}'
        )

        return response
