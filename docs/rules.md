# Rules and checks

What Squidbrake checks, how to configure it in `rules.yaml`, and how approvals work.

## Try it on real work first: observe mode

```bash
squidbrake connect all --mode observe     # or mode: observe in rules.yaml (shadow_agents: [...] for some agents)
squidbrake report --week                  # a week later: Markdown, or --json
```

In observe mode (also called shadow) Squidbrake blocks and holds nothing: it records what it *would* have done.
Stops, catastrophic commands (`rm -rf /`, wiping a drive) and an agent reaching for Squidbrake's own approval path are
enforced anyway. A rule or sequence can set its own `mode: enforce | observe`, so a team can enforce the catastrophic
ones first and observe the rest.

The weekly report (also `GET /v1/reports/week` and the Reports tab) has:

- actions seen, held and blocked, and what would have been held or blocked
- the **false-positive rate**, per rule and per week, from people marking a hold or block "This was legit" in the
  dashboard or with `squidbrake feedback EVENT_ID legit` (an agent can't mark its own)
- **decision time**, p50 / p95 / p99, recorded for every action
- the top 3 **chains** it caught, in plain words

## Command checks

A script, a Makefile target or a `package.json` script (including the `preinstall`, `install`, `postinstall` and `prepare` scripts `npm install` runs) is read line by line through the same checks, and the same `rules.yaml` rules, as a command typed directly. `npm install --ignore-scripts` runs none of them.

Shell tools (Claude Code's `Bash` and `PowerShell`, or any tool matching `command_checks.tools`) are read by
[`commands.py`](../commands.py) before the rules decide: the line is split on `&&`, `;`, `|` (outside quotes), and
`sudo`, `xargs`, `bash -c`, `powershell -Command`, `$(...)` and commands sent over `ssh`, `docker exec` or
`kubectl exec` are looked inside. Nothing is ever run or expanded.

| Kind | Examples | Default |
|---|---|---|
| catastrophic | `rm -rf /`, `rm -rf ~`, `rmdir /s /q d:\`, `mkfs`, `dd of=/dev/sda`, `chmod -R 777 /` | block |
| irreversible | `rm -r`, `git push --force`, `git reset --hard`, `terraform destroy`, `kubectl delete`, `aws ... delete-*`, `DROP TABLE` | review |
| hidden | `eval`, `curl ... \| sh`, `bash <(curl ...)`, `source <(...)`, `cat setup.sh \| bash`, `base64 -d \| bash`, `powershell -EncodedCommand`, `python -c` | review |
| secrets out | `curl -d "$(env)"`, `curl -F k=@~/.ssh/id_rsa`, `scp ~/.aws/credentials`, `nc ... < .env`: a send whose data is environment variables, SSH or cloud keys, `.env` or key files | review (irreversible) |
| downloaded_then_run | a file downloaded in this conversation, then run, sourced or made runnable (`curl -o x.sh URL`, then `sh x.sh`) | review |
| written_then_run | a script the agent wrote in this conversation, then runs (`python cleanup.py`) | review |
| edited_then_run | a script the agent changed in this conversation, then runs | warn (`review` holds it) |
| read_only | `ls`, `cat`, `grep`, `git status` / `log` / `diff` | `allow` in the shipped `rules.yaml` |

Command checks apply even when a rule allows the tool, and `read_only: allow` only relaxes the `default` (never a
rule or a warning). Configure them under `command_checks:` in `rules.yaml`.

## Terminal guard

Commands people paste from ChatGPT, a forum or a README never pass an agent hook. This puts the same command reader
([`commands.py`](../commands.py)) in front of your own shell: catastrophic lines are blocked, irreversible or unreadable
ones (`git push --force`, `curl ... | sh`) ask `Run it anyway? [y/N]`, everything else runs without a word. It works
offline, nothing is sent anywhere, and if the guard itself fails your command still runs.

```bash
squidbrake shell-guard install --shell bash >> ~/.bashrc        # then open a new terminal
squidbrake shell-guard install --shell zsh  >> ~/.zshrc
```

```powershell
if (!(Test-Path $PROFILE)) { New-Item -ItemType File -Force $PROFILE }
squidbrake shell-guard install --shell powershell | Add-Content $PROFILE
```

`install` only prints the snippet; it never edits a file, so read it first. Scripts and CI (non-interactive shells) are
never blocked or prompted. Each Enter starts Python, which adds about 150 ms. If bash already has a `DEBUG` trap (VS Code's shell integration, bash-preexec), the snippet leaves it alone and prints a warning. Check one line by hand: `squidbrake shell-guard check "rm -rf ~/"` (exit code 0 run, 1 block, 2 ask).

## Prompt injection, caught without a model

The attacks that actually happened to agents (a GitHub issue, a support ticket or a web page telling the agent to send
data somewhere) share one shape: the destination comes from content someone else wrote. Squidbrake records what you
ask (Claude Code prompts, via the hook) and which tools bring in outside content (`WebFetch`, inboxes, issues,
tickets...). When an action sends something to an email address, URL, bank account or repo that appears in that
outside content but not in what you asked or in your own systems' results, it's held with the reason:

> This sends to keys@evil.io (to), which appears in WebFetch (2 minutes ago) but not in anything you asked or in your
> own systems. Content from outside can carry hidden instructions (prompt injection).

Uploads from the shell count too (`curl -d @.env https://...`, `scp`, `git push`). Outside content read in one
conversation still counts in the next one, by any of the same person's agents (`taint_checks.scope: identity`; set
`session` to keep it to one conversation). Anything sent out after outside content was read in the same conversation
gets a warning for the approver. Configure it under `taint_checks:` in `rules.yaml`.

## Customer names and personal data in public places

Agents copy what they read: a ticket's customer ends up in a pull request description or a public issue. When an
agent puts text where other people read it (a PR, an issue or comment, a gist, a chat post, a page, and
`gh pr|issue|gist ... create|comment|edit`), it waits for a person if the text:

- names a customer on your list (dashboard → **Settings → Customers**), or
- carries personal data: a card number, a social security number, an IBAN, or a list of 3+ emails or phone numbers.

Looking things up (`list_issues`, `search_issues`) doesn't count, and email has its own rule. The approver sees which
customer it named, or which kind of data; the data itself isn't repeated. Configure it under `data_checks:` in
`rules.yaml` (`block`, `review`, `warn`, `off`).

## Sequence rules

Some actions are only dangerous because of what came before them. `sequences:` in `rules.yaml` judges an action by
the steps before it and names the step that caused the decision:

```yaml
sequences:
  - id: destroy-after-recovery-removed      # turn off backups, then delete the database
    action: review
    reason: Destroying data right after its backups or deletion protection were turned off
    match: { input_regex: 'delete[-_ ]?db[-_ ]?instance|terraform\s+destroy|drop\s+(table|database)' }
    after:
      match: { input_regex: 'backup[-_ ]?retention[-_ ]?period\W{0,4}0|deletion[-_ ]?protection\W{0,4}false' }
      within_hours: 24
  - id: runaway-refunds                     # an agent stuck in a loop
    action: deny
    reason: Too many refunds in a short time
    match: { name: ["*refund*"] }
    count: { more_than: 10, within_hours: 1, scope: identity }
```

The approver then sees, for example: *Destroying data right after its backups were turned off. Because earlier:
Bash `aws rds modify-db-instance --backup-retention-period 0` (12 minutes ago).* Actions: `deny`, `review` or `warn`.

- `after:` looks at earlier steps that went ahead (`same_target: true` = on the same charge, file or account).
- `count:` counts earlier matching actions.
- `scope:` sets where both look: `session` (one conversation), `agent`, `identity` (every conversation of every agent
  working for the same person: on your own computer all of them, on a team gateway the agents whose key works for
  that person) or `all`.

What earlier steps give an agent is kept until `within_hours` runs out, across restarts: `squidbrake capabilities`
lists the chains in progress.

## Human approval

Rules with `action: review` hold the call until a person approves or rejects it:

```yaml
- id: approve-payments
  action: review
  reason: Money movement needs a human
  timeout_seconds: 600     # default APPROVAL_TIMEOUT (300)
  on_timeout: deny         # or allow
  approvers: [alice, bob]  # optional; default = any approver key
  match: { name: "payments.*" }
```

- The first `POST /v1/events` returns `"decision": "review"`. **The Python client handles this for
  you**: `check()` and `@gw.guard` block until the call is decided, then run the tool or raise `Denied`.
  Other clients long-poll `GET /v1/events/{id}/decision?wait=25` until `decision` is `allow` or `deny`.
- To decide, use the **Needs approval** queue at the top of the dashboard, or call
  `POST /v1/events/{id}/approve` / `.../reject` with an optional `{"note": "..."}`.
- Only approver keys (`python server.py add-key NAME --approver`, and the rule's `approvers` if set) can decide,
  and **a key can never approve its own request**. So give people their own keys, separate from the agents' keys.
- If nobody decides before the deadline, `on_timeout` applies and `decided_by` is recorded as `timeout`.
- Every decision is stored on the event with who decided, when, and their note.
- Set `APPROVAL_WEBHOOK_URL` (plus `PUBLIC_URL`) to get a Slack- or Discord-formatted message with a link to the event
  whenever something needs approval.
- **Microsoft Teams and email:** in Settings, paste a Teams Workflows webhook ("Post to a channel when a webhook
  request is received"), or an SMTP server and the addresses to send to. Each approval links to the one-tap review
  page; an email never decides anything by being opened, since mail scanners open links.
- **Every Monday, what it caught:** Slack, Discord, Teams and email get the week's summary: what was blocked, rejected,
  or (in shadow mode) would have been, why, and what it would have changed. *Reports → What it caught* shows it any
  time, with *Copy weekly report*.
- **Stop asking about what you always approve:** *Settings → Rules* suggests an `allow` rule for anything people
  approved 5+ times in 30 days and never rejected (never for money, an agent's own setup, or what the command,
  data or chain checks held). *Allow it* adds the rule right before the one that held it, with a backup.
- **Starter packs** for a support, finance or ops agent add a block of rules after the read rule, so blocks above
  still win.
- **To your SIEM:** *Settings → Send to your SIEM* streams every decision to Splunk (HEC), Datadog (logs) or any HTTP
  endpoint, in batches in the background. Or set `SIEM_URL`, `SIEM_TOKEN`, `SIEM_FORMAT`.
- **Approve and Reject right in Slack:** in Settings, open *Approve and Reject right in Slack*, create the Slack app
  from the manifest shown there, install it to your approvals channel, and paste its webhook URL and signing secret.
  Each click is checked against the signing secret and carries that one event's signed token; the message then says
  who decided.
- Through the HTTP proxy, a held request stays open until it's decided, so the caller's HTTP
  timeout must be longer than the rule's `timeout_seconds`.

## Undo copies, spend limits, proof of work and signed approvals

- **Undo copies (`snapshots:` in rules.yaml, default `required`).** Before an action that waits for a person, or a
  command that can't be undone, runs, Squidbrake keeps a copy of what it changes: files and git changes on the agent's
  computer (`squidbrake undo`; Claude Code's Write and Edit too), the record behind an API call through `/proxy` (read
  with a GET first), or what your `client.py` snapshot function returns
  (`@gw.guard(snapshot=lambda args: db.get_order(args["order_id"]))`). If a copy is required and can't be made, the
  action doesn't run. A rule can set `snapshot: required | best_effort | off`; `required` on a rule also blocks paths
  that can't make a copy (MCP tools). The dashboard shows each copy and how to restore it.
- **Kill switch.** *Stop agents* in the dashboard or on the phone page stops one agent, one conversation or all of them.
  Phone notifications also carry a **Stop agent** button, and the one-tap approval page a *Stop* button.
- **Spend limits (`budgets:`).** Pause an agent once it has used N model tokens (or `usd:`) in a day or month, each on
  its own or several together. Claude Code's hook reports its tokens from the transcript; other agents send them to
  `POST /v1/usage` (`gw.usage(...)`). Reports shows each limit and what's used.
- **Proof of work (`proof_checks:`).** When an agent says an action is done, Squidbrake looks in the real system (Stripe,
  GitHub, a SQL database, or any HTTP API) with read-only credentials from the gateway's environment, and records
  *confirmed* or *not actually done*; a mismatch notifies a person.
- **Approvals signed by Face ID or fingerprint.** Register a phone or laptop as a passkey (Settings, or the phone page).
  Each approval made with it is signed by the device over exactly that decision and kept in the audit trail. Settings
  can require it for every approval (rejecting never needs it).
- **Access levels.** Owner, admin, approver and viewer. Viewers see everything and change nothing; only owners make
  admins and owners, and a team always keeps one owner. Teams such as `finance` still work for `approvers: [role:finance]`.
- **AI approval briefs.** Off until an admin adds the team's own Anthropic key: a short, plain-English risk note on each
  held action, written from what the dashboard shows (redacted). Advice only.
