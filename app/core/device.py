"""Basic device identification from the User-Agent header (plan: UA + IP, not
exotic fingerprinting). Two jobs: a human-friendly name, and a stable fingerprint
used to match trusted devices.
"""

import hashlib


def device_name_from_ua(user_agent: str | None) -> str:
    """Heuristic 'Browser on OS' label, e.g. 'Chrome on Windows'. Good enough for
    a session list; not meant to be exhaustive."""
    if not user_agent:
        return "Unknown device"
    ua = user_agent

    # order matters: Edge/Chrome both contain "Chrome"; check the specific ones first
    if "Edg" in ua:
        browser = "Edge"
    elif "OPR" in ua or "Opera" in ua:
        browser = "Opera"
    elif "Firefox" in ua:
        browser = "Firefox"
    elif "Chrome" in ua:
        browser = "Chrome"
    elif "Safari" in ua:
        browser = "Safari"
    else:
        browser = "Browser"

    if "Windows" in ua:
        os_name = "Windows"
    elif "Android" in ua:
        os_name = "Android"
    elif "iPhone" in ua or "iPad" in ua or "iOS" in ua:
        os_name = "iOS"
    elif "Mac OS" in ua or "Macintosh" in ua:
        os_name = "macOS"
    elif "Linux" in ua:
        os_name = "Linux"
    else:
        os_name = "Unknown OS"

    return f"{browser} on {os_name}"


def device_fingerprint(user_agent: str | None) -> str:
    """SHA-256 of the raw User-Agent. Same browser+OS+version → same fingerprint,
    so a 'remembered' device is recognized on the next login."""
    return hashlib.sha256((user_agent or "").encode()).hexdigest()


def demo() -> None:
    chrome_win = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36"
    assert device_name_from_ua(chrome_win) == "Chrome on Windows"
    edge = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 Chrome/120 Safari/537.36 Edg/120"
    assert device_name_from_ua(edge) == "Edge on Windows"
    assert device_name_from_ua(None) == "Unknown device"
    assert device_fingerprint(chrome_win) == device_fingerprint(chrome_win)
    assert device_fingerprint(chrome_win) != device_fingerprint(edge)
    print("device.py demo OK")


if __name__ == "__main__":
    demo()
