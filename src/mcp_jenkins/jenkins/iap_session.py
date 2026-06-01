import re
from urllib.parse import urlparse

import browser_cookie3
import requests
from loguru import logger

_MASK_RE = re.compile(r'(=[^;]{8})[^;]*')


def _mask_cookie_header(header: str) -> str:
    """Show first 8 chars of each cookie value, mask the rest."""
    return _MASK_RE.sub(r'\1…', header)


def _load_iap_cookies(domain: str, chrome_profile: str | None) -> dict[str, str]:
    """Read IAP cookies from Chrome for the given domain.

    Tries the exact domain first, then with a leading dot, across the
    specified Chrome profile (or all profiles if None).
    """
    kwargs = {}
    if chrome_profile:
        kwargs['cookie_file'] = _chrome_cookie_path(chrome_profile)

    iap_cookies: dict[str, str] = {}
    for query_domain in (domain, f'.{domain}'):
        try:
            cj = browser_cookie3.chrome(domain_name=query_domain, **kwargs)
            all_cookies = {c.name: c.value for c in cj}
            found = {k: v for k, v in all_cookies.items() if 'IAP' in k.upper()}
            logger.debug(
                f'Chrome cookie lookup for {query_domain!r}'
                f'{" (profile: " + chrome_profile + ")" if chrome_profile else ""}: '
                f'{len(all_cookies)} total, {len(found)} IAP — '
                f'names: {list(found.keys()) or "(none)"}'
            )
            iap_cookies.update(found)
        except Exception as exc:
            logger.warning(f'Failed to read Chrome cookies for {query_domain!r}: {exc!r}')

    return iap_cookies


def _chrome_cookie_path(profile_name: str) -> str:
    """Return the Cookies DB path for a named Chrome profile."""
    import platform
    from pathlib import Path

    system = platform.system()
    if system == 'Darwin':
        base = Path.home() / 'Library' / 'Application Support' / 'Google' / 'Chrome'
    elif system == 'Linux':
        base = Path.home() / '.config' / 'google-chrome'
    elif system == 'Windows':
        base = Path.home() / 'AppData' / 'Local' / 'Google' / 'Chrome' / 'User Data'
    else:
        msg = f'Unsupported platform for Chrome cookie lookup: {system}'
        raise RuntimeError(msg)

    cookie_path = base / profile_name / 'Cookies'
    logger.debug(f'Resolved Chrome cookie DB path: {cookie_path}')
    return str(cookie_path)


class IAPSession(requests.Session):
    """A requests.Session that injects live IAP cookies from Chrome on every request.

    Reads cookies fresh from the local Chrome cookie store per-request so that
    IAP session refreshes mid-run are picked up automatically.
    """

    def __init__(self, iap_domain: str, chrome_profile: str | None = None, **kwargs) -> None:
        super().__init__(**kwargs)
        self._iap_domain = iap_domain
        self._chrome_profile = chrome_profile
        logger.info(
            f'IAPSession initialised for domain: {iap_domain}'
            f'{", chrome_profile: " + chrome_profile if chrome_profile else ""}'
        )

    def request(self, method, url, **kwargs):
        domain = urlparse(url).hostname or self._iap_domain
        iap_cookies = _load_iap_cookies(domain, self._chrome_profile)

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
