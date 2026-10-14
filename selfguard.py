"""
Squidbrake protecting itself from the agents it watches. Checked in code, before rules.yaml and in shadow mode too,
so no edit to the rules can loosen it.

  approval  (blocked)  the ways an agent could approve its own held action: reading or writing Squidbrake's keys,
                       link secret and database; minting a key with `squidbrake add-key`; calling the approval API
                       from its own tools; reading the browser storage where the dashboard keeps a person's key
  tamper    (held)     the ways an agent could loosen Squidbrake: editing the installed package, installing another
                       version of it, a lasting GATEWAY_* / SQUIDBRAKE_* variable, a second gateway with auth off

What this can't see is in THREAT_MODEL.md.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

# Files in the gateway's data folder an agent must never read or write: who may approve, the secret that signs
# approval links, the ledger key and the record itself.
OWN_FILES = ("keys.json", "secret.key", "ledger.key", "gateway.db", "pilot.json", "integrity.json")

# Commands that change who may approve, undo a person's stop, or mark a block as a false positive: a person runs
# these, in their own terminal.
KEY_ADMIN_RE = re.compile(
    r"(?i)\b(squidbrake(\.exe)?|server\.py)[\"']?\s+(add-key|remove-key|init|resume|feedback|integrity)\b")

# The approval API, reached from the agent's own tools (curl, fetch, a script): deciding, or lifting a stop. (The team
# and settings endpoints need a person's key, which the checks here keep out of an agent's reach.)
APPROVAL_API_RE = re.compile(
    r"(?i)/v1/(a/[^/\s\"']+/(approve|reject|challenge)|events/[^/\s\"']+/(approve|reject|challenge|feedback)|controls/resume|integrity/accept)\b")

# Where browsers keep the dashboard's key (and every cookie): never everyday work for an agent.
BROWSER_STORE_RE = re.compile(
    r"(?i)(Google[\\/]+Chrome|Microsoft[\\/]+Edge|BraveSoftware|Chromium|Vivaldi|Opera Software)[\\/]+.*"
    r"(User Data|Default|Profile)|\.mozilla[\\/]+firefox|Firefox[\\/]+Profiles|Library[\\/]+Safari|"
    r"Local Storage[\\/]+leveldb|\.config[\\/]+(google-chrome|chromium|BraveSoftware)")

# The installed gateway and hooks (not a checkout being worked on, which is everyday work).
PACKAGE_RE = re.compile(
    r"(?i)(site|dist)-packages[\\/]+(squidbrake\b|claude_hook\.py|agent_hook\.py|server\.py|offline\.py|commands\.py)|"
    r"(pipx|uv[\\/]+tools)[\\/]+(venvs[\\/]+)?squidbrake\b")
REINSTALL_RE = re.compile(r"(?i)\b(pip3?|uv|pipx)\b[^|;&\n]*\b(install|add|inject)\b[^|;&\n]*\bsquidbrake\b")
LASTING_ENV_RE = re.compile(
    r"(?i)(\bsetx\b|SetEnvironmentVariable|launchctl\s+setenv|systemctl\s+(--user\s+)?set-environment)"
    r"[^|;&\n]*\b(GATEWAY|SQUIDBRAKE)_\w+")
AUTH_OFF_RE = re.compile(r"(?i)\bGATEWAY_AUTH\s*=\s*[\"']?(off|disabled|false|0|no)\b")


def _norm(p: str) -> str:
    return os.path.normcase(os.path.normpath(os.path.expanduser(p.replace("\\", "/")))).replace("\\", "/")


def _strings(value) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _touches_data(texts: list[str], cwd: str, data_dir: Path) -> str | None:
    """The file in Squidbrake's data folder this input names, by absolute path, ~, or relative to the cwd."""
    data = _norm(str(data_dir))
    for text in texts:
        flat = text.replace("\\\\", "/").replace("\\", "/")
        if data in _norm(flat) or re.search(r"(?i)\.squidbrake/+data\b", flat):
            return data
        for token in re.findall(r"[^\s'\"=<>|;&()]+", flat):
            if not any(f in token.lower() for f in OWN_FILES):
                continue
            here = _norm(os.path.join(cwd, token)) if cwd and not os.path.isabs(os.path.expanduser(token)) else _norm(token)
            if here.startswith(data + "/") or here == data or re.search(r"(?i)\.squidbrake/+data/", here):
                return here
    return None


def check(kind: str | None, name: str, input, metadata: dict | None, data_dir: Path) -> dict | None:
    """-> {"check": "approval" | "tamper", "effect": "block" | "review", "message"} or None."""
    if kind == "prompt":
        return None
    texts = _strings(input)
    if not texts:
        return None
    cwd = str((metadata or {}).get("cwd") or "")
    joined = "\n".join(texts)
    say = lambda check, effect, message: {"check": check, "effect": effect, "message": message}
    if (hit := _touches_data(texts, cwd, data_dir)) is not None:
        return say("approval", "block", f"This reads or changes Squidbrake's own keys and records ({hit}). An agent "
                                        "can't: with them it could approve its own actions.")
    if m := KEY_ADMIN_RE.search(joined):
        return say("approval", "block", f"This runs `{m.group(0).strip()[:80]}`, which changes who may approve or "
                                        "lifts a stop. A person does that in their own terminal, not an agent.")
    if m := APPROVAL_API_RE.search(joined):
        return say("approval", "block", f"This calls Squidbrake's approval API ({m.group(0)}) from the agent's own "
                                        "tools. Approvals come from a person, in the dashboard, on their phone or in Slack.")
    if BROWSER_STORE_RE.search(joined):
        return say("approval", "block", "This reads a browser's profile (cookies, saved keys and sign-ins, including "
                                        "the dashboard's). An agent has no business there.")
    if m := (PACKAGE_RE.search(joined) or REINSTALL_RE.search(joined) or LASTING_ENV_RE.search(joined)
             or AUTH_OFF_RE.search(joined)):
        return say("tamper", "review", f"This changes Squidbrake itself ({m.group(0).strip()[:80]}): the installed "
                                       "program, a setting that loosens it, or a gateway with sign-in off.")
    return None


if __name__ == "__main__":     # a quick look: python selfguard.py '{"command": "squidbrake add-key x"}'
    import sys
    print(check("tool_call", "Bash", json.loads(sys.argv[1]), {"cwd": os.getcwd()},
                Path.home() / ".squidbrake" / "data"))
