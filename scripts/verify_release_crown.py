from __future__ import annotations

import argparse
import json
import re
import tomllib
from pathlib import Path

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ALLOWED_STANDING = {"UNKNOWN", "PARTIAL_ALIVE", "ALIVE", "BLOCKED", "BUILD_BROKEN", "UNSUPPORTED"}
REQUIRED_ROLES = {"planning_control", "cmca", "orchestration", "world_execution", "standing_federation"}


def verify(path: Path) -> dict[str, object]:
    data = tomllib.loads(path.read_text())
    if data.get("schema") != "autofde.release-crown/1":
        raise ValueError("REFUSED:RELEASE_SCHEMA")
    if data.get("release") != "26.9.1":
        raise ValueError("REFUSED:RELEASE_IDENTITY")
    if data.get("claim_ceiling") != "RELEASE_CANDIDATE_COMPOSITION_ONLY_NO_TRANSITIVE_AUTHORITY":
        raise ValueError("REFUSED:CLAIM_CEILING")
    components = data.get("components")
    if not isinstance(components, list) or not components:
        raise ValueError("REFUSED:EMPTY_COMPONENT_SET")
    roles: dict[str, dict[str, object]] = {}
    for component in components:
        role = component.get("role")
        if not isinstance(role, str) or role in roles:
            raise ValueError("REFUSED:DUPLICATE_OR_INVALID_ROLE")
        revision = component.get("revision")
        standing = component.get("standing")
        if not isinstance(revision, str) or not SHA_RE.fullmatch(revision):
            raise ValueError(f"REFUSED:INVALID_REVISION:{role}")
        if standing not in ALLOWED_STANDING:
            raise ValueError(f"REFUSED:INVALID_STANDING:{role}")
        if standing == "ALIVE" and not component.get("execution_receipt"):
            raise ValueError(f"REFUSED:ALIVE_WITHOUT_EXECUTION:{role}")
        if standing == "BLOCKED" and not component.get("blocker"):
            raise ValueError(f"REFUSED:BLOCKED_WITHOUT_REASON:{role}")
        if component.get("authority") == "AMBIENT_DO":
            raise ValueError(f"REFUSED:AMBIENT_DO:{role}")
        roles[role] = component
    missing = sorted(REQUIRED_ROLES - roles.keys())
    if missing:
        raise ValueError("REFUSED:MISSING_REQUIRED_ROLE:" + ",".join(missing))
    unresolved = sorted(role for role in REQUIRED_ROLES if roles[role].get("standing") != "ALIVE")
    return {
        "release": "26.9.1",
        "standing": "ALIVE" if not unresolved else "PARTIAL_ALIVE",
        "required_roles": sorted(REQUIRED_ROLES),
        "unresolved_required_roles": unresolved,
        "do_authority": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.path), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
