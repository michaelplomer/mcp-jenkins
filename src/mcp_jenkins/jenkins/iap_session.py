from urllib.parse import urlparse

import browser_cookie3
import requests
from loguru import logger


class IAPSession(requests.Session):
    """A requests.Session that injects live IAP cookies from Chrome on every request.

    Reads cookies fresh from the local Chrome cookie store per-request so that
    IAP session refreshes mid-run are picked up automatically.
    """

    def __init__(self, iap_domain: str, **kwargs) -> None:
        super().__init__(**kwargs)
        self._iap_domain = iap_domain

    def request(self, method, url, **kwargs):
        domain = urlparse(url).hostname or self._iap_domain
        try:
            cj = browser_cookie3.chrome(domain_name=f'.{domain}')
            iap_cookies = {c.name: c.value for c in cj if 'IAP' in c.name.upper()}
        except Exception:
            logger.warning(f'Failed to read Chrome cookies for {domain} — sending request without IAP cookie')
            iap_cookies = {}

        if iap_cookies:
            existing = kwargs.get('headers') or {}
            parts = [f'{name}={value}' for name, value in iap_cookies.items()]
            if 'Cookie' in existing:
                parts.insert(0, existing['Cookie'])
            existing['Cookie'] = '; '.join(parts)
            kwargs['headers'] = existing
            logger.debug(f'Injected {len(iap_cookies)} IAP cookie(s) for {domain}')

        return super().request(method, url, **kwargs)
