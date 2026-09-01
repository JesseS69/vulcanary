from __future__ import annotations

import json
import re
from urllib.request import Request, urlopen

from .version import __version__


def _version_tuple(value: str) -> tuple[int, ...]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value.strip())
    if not match:
        raise ValueError("Release tag is not a semantic version")
    return tuple(int(part) for part in match.groups())


def check_for_update(timeout: int = 5) -> dict:
    request = Request(
        "https://api.github.com/repos/JesseS69/vulcanary/releases/latest",
        headers={"Accept": "application/vnd.github+json", "User-Agent": f"Vulcanary/{__version__}"},
    )
    with urlopen(request, timeout=timeout) as response:  # nosec B310 -- fixed official Vulcanary release endpoint.
        payload = json.loads(response.read())
    tag = payload.get("tag_name") if isinstance(payload, dict) else None
    url = payload.get("html_url") if isinstance(payload, dict) else None
    if not isinstance(tag, str) or not isinstance(url, str) or not url.startswith("https://github.com/JesseS69/vulcanary/releases/"):
        raise ValueError("GitHub returned an invalid Vulcanary release record")
    return {"current": __version__, "latest": tag.removeprefix("v"), "update_available": _version_tuple(tag) > _version_tuple(__version__), "url": url}
