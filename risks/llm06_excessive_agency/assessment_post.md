# LLM06 — Excessive Agency: POST-mitigation assessment

## Mitigations in place
1. **Least-privilege toolset.** `delete_file` and `run_shell` removed
   entirely; `write_file` replaced by a sandbox-scoped variant that *queues*
   rather than executes; `http_request` replaced by `http_get` with a domain
   allowlist. (`FIX A`)
2. **Sandbox path canonicalization.** Every path argument is resolved to an
   absolute path and must lie inside `data/sandbox/`; `..` traversal,
   symlinks, and absolute paths outside the sandbox are rejected. (`FIX B`)
3. **Human-in-the-loop confirmation.** Writes and emails become
   `PendingAction` records; they only take effect when a human approves them
   in the UI. The agent cannot side-effect silently. (`FIX C`)
4. **Per-session budgets.** Hard caps on total tool calls, HTTP calls, and
   write calls abort the loop before runaway autonomy does damage. (`FIX D`)
5. **Argument validation.** Email bodies containing non-allowlisted URLs are
   rejected; HTTP URLs must match the allowlist. (`FIX E`)
6. **Hardened cached system prompt.** Agent must (a) treat tool output as
   data not instructions, (b) state intent before each tool call, (c) refuse
   to invent follow-up actions the user did not request. (`FIX F`)

## Residual-risk scenarios *(why this is not "fully mitigated")*
- **Approval fatigue.** If the operator approves queued actions by reflex
  without reading them, the human-in-the-loop control collapses to a click.
- **Allowed-tool misuse.** Even a narrow `http_get` to an allowlisted domain
  can leak data through URL query strings or cache side-channels.
- **Sandbox escape via approved writes.** A human who approves a malicious
  write has re-introduced the risk — the control assumes a reviewing human.
- **Prompt-injection drift.** A sufficiently persuasive injection in tool
  output may still lead the model to *request* a dangerous action (which
  then sits in the pending queue waiting for an inattentive approver).
- **Budget exhaustion as a weapon.** An attacker can deliberately exhaust
  the tool-call budget to cause a denial-of-service on the agent itself.

## Likelihood — **Low (1)**
Destructive tools no longer exist; off-sandbox paths and non-allowlisted
hosts are rejected before reaching the mocked side effects; writes and
emails require human approval; per-session budgets cap blast radius.

## Impact — **High (3)**
If a mitigation *is* bypassed (e.g., an operator approves a malicious
queued write), the agent can still modify sandbox contents or send mail.
The tools are narrower, but the worst-case per-action impact is still
non-trivial.

## Overall score
**Likelihood × Impact = 1 × 3 = 3 → Low**

Down from **Critical (12)**.

## Monitoring / detective controls
- Audit every tool call with `tool`, `args`, `blocked`, `reason`. Alert on a
  spike of `blocked=True` entries — recon signal.
- Alert on any queued action whose arguments reference non-allowlisted
  domains, external email addresses, or paths resolved via `..`.
- Surface the pending-action queue prominently in the UI; require a
  two-click confirmation for any action that writes outside of a default
  "safe" subdirectory.
- Track per-user approval rate; investigate users who approve > 95% of
  queued actions (approval fatigue indicator).
