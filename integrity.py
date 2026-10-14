"""
Has anything changed Squidbrake underneath it? On start and every minute the gateway compares, with the copy it
made the first time (data/integrity.json):

  hooks      Squidbrake's own hook lines in each agent's config (other settings in those files may change freely)
  package    the installed program's files (a pip / uv / pipx install; a checkout being worked on isn't checked)
  rules      rules.yaml (a person edits it, so this only alerts; the policy history keeps every version anyway)

A change is put on the record (integrity.changed), sent wherever approvals go, and, with rules.yaml
`integrity: fail_closed`, actions that can't be undone are blocked until a person runs `squidbrake integrity accept`.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

NAME = "integrity.json"


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def hook_lines(path: Path) -> str | None:
    """The Squidbrake hook commands in an agent's config, fingerprinted (None: no such file)."""
    import connect
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError:
        return None
    except (OSError, ValueError):
        return "unreadable"
    return _sha("\n".join(sorted(connect._hook_commands(data))).encode())


def current(rules: Path, package: Path | None, hooks: dict[str, Path]) -> dict[str, dict[str, str | None]]:
    state: dict[str, dict[str, str | None]] = {"hooks": {}, "package": {}, "rules": {}}
    for agent, path in hooks.items():
        state["hooks"][agent] = hook_lines(path)
    if package is not None:
        for f in sorted(package.rglob("*.py")):
            if "__pycache__" not in f.parts:
                state["package"][f.relative_to(package).as_posix()] = _sha(f.read_bytes())
    try:
        state["rules"]["rules.yaml"] = _sha(rules.read_bytes().replace(b"\r\n", b"\n"))
    except OSError:
        state["rules"]["rules.yaml"] = None
    return state


def compare(data_dir: Path, now: dict) -> list[dict]:
    """What differs from the copy kept the first time (made now if there is none). -> [{kind, what, change}]"""
    path = data_dir / NAME
    try:
        was = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        accept(data_dir, now)
        return []
    out = []
    for kind in ("hooks", "package", "rules"):
        before, after = was.get(kind) or {}, now.get(kind) or {}
        for what in sorted(set(before) | set(after)):
            if before.get(what) != after.get(what):
                change = "removed" if after.get(what) is None else "added" if before.get(what) is None else "changed"
                out.append({"kind": kind, "what": what, "change": change})
    return out


def accept(data_dir: Path, now: dict) -> None:
    data_dir.mkdir(parents=True, exist_ok=True)
    (data_dir / NAME).write_text(json.dumps(now, indent=1), encoding="utf-8")


def describe(changes: list[dict]) -> str:
    words = {"hooks": "Squidbrake's hook in", "package": "the installed file", "rules": ""}
    return "; ".join(f"{words[c['kind']]} {c['what']} {c['change']}".strip() for c in changes[:8]) + \
        (f" and {len(changes) - 8} more" if len(changes) > 8 else "")
