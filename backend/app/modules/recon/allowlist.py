"""Optional recon target allowlist (production / lab hardening)."""
from __future__ import annotations

import ipaddress
import re
from ipaddress import AddressValueError, NetmaskValueError

from app.core.config import settings
from app.core.logging import get_logger

log = get_logger(__name__)


def target_matches_allowlist(value: str) -> bool:
    """If ``RECON_TARGET_ALLOWLIST`` is non-empty, the target must match at least
    one entry: exact/suffix domain, exact IPv4, or IP contained in a CIDR.
    If the setting is empty, all targets are allowed (development default).
    """
    raw = (settings.recon_target_allowlist or "").strip()
    if not raw:
        return True

    v = value.strip()
    v_lower = v.lower()

    for part in re.split(r"[\s,;]+", raw):
        entry = part.strip()
        if not entry:
            continue
        e = entry.lower()

        if _looks_like_ip_or_cidr(e):
            if _ip_targets_match(v, e):
                return True
        else:
            if v_lower == e or v_lower.endswith(f".{e}"):
                return True

    log.warning("recon.target.denied", value=v[:120])
    return False


def _looks_like_ip_or_cidr(s: str) -> bool:
    return "/" in s or (s.replace(".", "").isdigit() and s.count(".") == 3)


def _ip_targets_match(v: str, e: str) -> bool:
    try:
        if "/" in e:
            net = ipaddress.ip_network(e, strict=False)
            if "/" in v:
                return net.overlaps(ipaddress.ip_network(v, strict=False))
            return ipaddress.ip_address(v) in net
        if "/" in v:
            return False
        return ipaddress.ip_address(v) == ipaddress.ip_address(e)
    except (AddressValueError, NetmaskValueError, ValueError):
        return False
