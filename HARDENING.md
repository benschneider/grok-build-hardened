# Grok Build Hardening

Security analysis and hardening roadmap for this fork of SpaceXAI’s open-sourced
**Grok Build** (`grok`) agent CLI/TUI.

Upstream: published for source transparency under Apache-2.0; external PRs are
not accepted there. This repository is an independent hardening effort.

---

## 1. What this product is

Grok Build is a terminal AI coding agent with a large trusted computing base:

| Layer | Crates (representative) | Capability |
|-------|-------------------------|------------|
| TUI | `xai-grok-pager*` | Full-screen UI, clipboard, rendering |
| Agent runtime | `xai-grok-shell` | Sessions, auth, sampling, ACP, headless |
| Tools | `xai-grok-tools` | Shell, FS edit, web fetch/search, media, tasks |
| Workspace / permissions | `xai-grok-workspace` | Policy, shell AST analysis, path rules (~20k LOC) |
| Sandbox | `xai-grok-sandbox` | Landlock / Seatbelt / bwrap deny paths |
| Extensibility | MCP, hooks, plugins, skills, marketplace | Untrusted code + network (MCP kill-switch WIP on `no-mcp` branch) |
| Update | `xai-grok-update` | Auto-download and replace binary |
| Secrets | `xai-grok-secrets` | Log/output redaction |

Rough scale: **~2,100+ Rust source files**, multi-crate workspace, heavy
`unsafe` at OS boundaries (seccomp, prctl, flock).

---

## 2. Threat model

### Assets

- Host filesystem (source, secrets, SSH keys, cloud credentials)
- Network identity (tokens in `~/.grok/auth.json`, API keys)
- Integrity of the `grok` binary (supply chain / auto-update)
- User trust in permission prompts (social-engineering via model output)
- Corporate environments (managed config under `/etc/grok/`)

### Adversaries

1. **Prompt-injected model / untrusted repo content** — primary threat for an
   agent that runs shell and edits files.
2. **Malicious MCP server / plugin / hook** — code execution and network.
3. **Network attacker** — SSRF to metadata, MITM of update CDN, DNS rebinding.
4. **Local malware / multi-user host** — world-readable secrets, race on auth files.
5. **Compromised dependency** — crates.io / git deps in a huge graph.

### Out of scope (for now)

- Defending against a fully compromised OS kernel
- Side-channel crypto attacks on auth tokens
- Guaranteeing model behavior (non-determinism); we harden *enforcement*

---

## 3. Existing defenses (strengths)

The upstream tree already invests heavily in safety:

### Permission pipeline (`xai-grok-workspace`)

Ordered authorization: PreToolUse hooks → deny/ask/allow rules → remembered
grants → built-in read-only auto-approvals → mode policy
(`default` / `dontAsk` / `bypassPermissions` / `acceptEdits`).

Shell analysis is unusually strong for an agent product:

- Tree-sitter bash splitting closes `safe && dangerous` auto-allow bypasses
- Wrapper peeling (`timeout`, `env`, `nice`, …) before classification
- Word-boundary allow prefixes (CWE-183: `git` ⊄ `gitleaks`)
- `is_dangerous_command_words` never auto-allows via whitelist (`rm`, `chmod`,
  `chown`, `kill*`, `git push`, …)
- Shell file-access analysis escalates Read/Edit denies through redirects and
  common reader/writer binaries, including symlink target re-check

### OS sandbox (`xai-grok-sandbox`)

- Kernel enforcement via **nono** (Landlock Linux / Seatbelt macOS)
- Profiles: `off` (default), `workspace`, `devbox`, `read-only`, `strict`
- Deny paths/globs fail **closed** when they cannot be enforced
- Linux child-network seccomp + `PR_SET_NO_NEW_PRIVS`
- macOS: documented that child-network restriction is a no-op

### Web / hooks SSRF

- `web_fetch`: private/link-local/CGNAT/metadata ranges blocked; redirects
  manual and same-host only; `redirect::Policy::none()`
- HTTP hooks: SSRF validation post-env-expansion with tests

### Secrets redaction (`xai-grok-secrets`)

- Regex coverage for common vendor keys, PEM, Bearer, JWT, assignment forms,
  sensitive query params, home-path scrubbing

### Credentials

- **MCP removed entirely** in this fork (crates, runtime spawn, OAuth, CLI,
  `search_tool`/`use_tool`). Not a kill-switch — code deleted.

### Fail-closed design notes

Many security-sensitive paths already document fail-closed intent (deny glob
expansion, unparseable shell → prompt, classifier unavailable → block).

---

## 4. Findings and gaps (prioritized)

Severity is for a **local developer running the agent with network + tools**,
assuming prompt injection or a malicious page/MCP as the entry point.

### P0 — High impact / realistic exploit path

| ID | Finding | Notes |
|----|---------|--------|
| **H-01** | **Sandbox off by default** | Docs: “Sandbox mode is off by default.” Kernel isolation is opt-in. |
| **H-02** | **Sandbox apply fails open** | On unsupported platform or `Sandbox::apply` error: log warning and continue **without** sandbox (`lib.rs`). User may believe `--sandbox workspace` is active. |
| **H-03** | **`web_fetch` DNS rebinding (CWE-918)** | `check_ssrf` resolves + validates IPs, then reqwest resolves again on connect. Classic TOCTOU. No IP pin / custom resolver. |
| **H-04** | **Auto-update trust** | Downloads from `https://x.ai/cli` / GCS fallback. No in-tree evidence of artifact **checksum / signature verification** before replace. HTTPS-only is necessary but not sufficient against CDN/account compromise. |
| **H-05** | **Hooks fail-open on SSRF block** | Integration test: SSRF-blocked HTTP hook does **not** block the tool call. Fail-open is intentional for hook infrastructure failure — attackers who can install hooks may still force open behavior depending on config source. |

### P1 — Important hardening

| ID | Finding | Notes |
|----|---------|--------|
| **H-06** | **Dangerous-command list is short** | Only: `rm`, `chmod`/`chown`/`chgrp`/`chattr`, `kill`/`pkill`/`killall`, `git push`. Missing common high-risk: `sudo`/`doas`, `dd`, `mkfs*`, `shutdown`/`reboot`, `curl`/`wget` piped patterns (harder), `python -c` / `node -e`, `diskutil`, `launchctl`, `systemctl`, `crontab`, etc. |
| **H-07** | **Child seccomp incomplete** | Blocks `connect`/`bind`/`sendto`/`sendmsg`/`listen`/`accept*`. Does not block e.g. `sendmmsg`, `connect` via `io_uring`, or broader socket setup. Linux-only; macOS unrestricted. |
| **H-08** | **macOS child network unrestricted** | Documented. `read-only`/`strict` network story is weaker on Darwin. |
| **H-09** | **Linux deny globs are launch-time only** | Files matching `**/.env` created after start are not covered (docs). macOS Seatbelt regex is airtight. |
| **H-10** | **Plugin / marketplace trust** | Install path copies git/local trees into managed storage; capability depends on later skill/hook execution model. Need install-time scanning + permission boundary. |
| **H-11** | **MCP surface** | **Mitigated:** MCP crates and runtime deleted in this fork. |
| **H-12** | **JWT `insecure_decode`** | Used for claim extraction in auth paths — ensure never used as *verification* for authorization decisions. |

### P2 — Defense in depth / process

| ID | Finding | Notes |
|----|---------|--------|
| **H-13** | **No cargo-deny / cargo-audit in tree** | No `deny.toml` / Dependabot-style automation in this publish tree. |
| **H-14** | **Secrets redaction is best-effort** | Regex can miss novel formats; does not prevent model from *reading* secrets via tools. |
| **H-15** | **`bypassPermissions` / always-approve** | Powerful; lockable via `/etc/grok/requirements.toml` — good enterprise control; document for hardened defaults. |
| **H-16** | **Prompt injection → exfil** | Even with sandbox, `workspace` profile allows read-everywhere + network. Strict profile needed for untrusted code. |
| **H-17** | **Loopback allowed in SSRF** | Intentional for local dev (`127.0.0.0/8`, `::1`). Risky on multi-service laptops (databases, admin UIs). |

---

## 5. Hardening principles (this fork)

1. **Fail closed** when the user requested a security control (sandbox profile,
   deny paths, SSRF). Prefer refuse-to-start over silent degradation.
2. **Never re-resolve untrusted hostnames** after an allow decision without
   re-validation (DNS pin).
3. **Default-secure profiles** for CI/headless (`dontAsk` + sandbox + deny
   secrets globs).
4. **Measure** — tests for each closed bypass; regression tests stay next to
   the control.
5. **Minimal product friction** — aggressive prompts only for high-risk ops;
   expand dangerous lists carefully with tests.

---

## 6. Roadmap

### Phase 0 — Baseline (this PR / week 1)

- [x] Threat model + gap analysis (`HARDENING.md`)
- [x] Supply-chain scaffolding (`deny.toml`; run `cargo deny check`)
- [x] **H-03**: DNS-pin `web_fetch` after SSRF allow (`resolve_to_addrs`)
- [x] **H-06** (partial): expand dangerous-command program list + tests
- [x] Document recommended hardened launch flags + `examples/hardened-sandbox.toml`

### Phase 1 — Isolation defaults

- [ ] **H-02**: Optional / default fail-closed when `--sandbox` is set but apply fails
- [ ] **H-01**: Recommend `workspace` or `strict` as default in this fork (config)
- [ ] Default deny globs for secrets: `**/.env`, `**/*.pem`, `**/id_rsa`, `**/.aws/credentials`
- [ ] Headless CI profile template (`.grok/hardened.toml` example)

### Phase 2 — Network & update

- [ ] **H-04**: Require signed or hashed artifacts for auto-update (cosign/minisign/sha256 sidecar)
- [ ] **H-07/H-08**: Strengthen child net (more syscalls; explore macOS network sandbox)
- [ ] **H-17**: Config flag to block loopback in SSRF
- [ ] Re-validate SSRF on every redirect hop (defense in depth)

### Phase 3 — Extensibility audit

- [x] MCP removed entirely (delete crates + call sites; see this section)
- [ ] Hooks: configurable fail-closed for security-critical events
- [ ] Plugin marketplace: provenance, hash pin, capability manifest
- [ ] Skills: no silent shell from untrusted skill content

### Phase 4 — Continuous assurance

- [ ] `cargo audit` / `cargo deny` in CI
- [ ] Fuzz targets for shell policy AST and permission matching
- [ ] Adversarial prompt-injection test suite (golden denials)
- [ ] SBOM generation for releases

---

## 7. Recommended hardened invocation (today)

```bash
# Interactive, daily use on a trusted machine
grok --sandbox workspace

# Untrusted repo / code review
grok --sandbox strict \
  --deny 'Bash(rm *)' \
  --deny 'Bash(sudo *)' \
  --deny 'Bash(curl *)' \
  --deny 'Bash(wget *)'

# Headless CI (deny-by-default prompt policy via Claude settings)
# In .claude/settings.json: "defaultMode": "dontAsk"
grok -p --sandbox strict --allow 'Bash(cargo test *)' --allow 'Read' --allow 'Grep'
```

Custom deny secrets (kernel-enforced when sandbox active):

```toml
# ~/.grok/sandbox.toml or .grok/sandbox.toml
[profiles.hardened]
extends = "workspace"
restrict_network = true
deny = ["**/.env", "**/*.pem", "**/*.key", "**/.ssh/**", "**/.aws/**"]
```

```bash
grok --sandbox hardened
```

---

## 8. Attack surface map (quick reference)

```
User / model
    │
    ▼
Permission manager ── hooks (PreToolUse) ── rules ── dangerous list ── mode
    │
    ├─► bash ────────── sandbox FS/net ── shell AST file-access
    ├─► read/edit ───── Landlock/Seatbelt
    ├─► web_fetch ───── SSRF + domain allowlist
    ├─► web_search ──── outbound API
    ├─► MCP tools ───── child process / HTTP
    └─► plugins/skills ─ discovered code paths

Auth tokens ── ~/.grok/auth.json
Update ─────── x.ai/cli + GCS ──► replace binary
```

---

## 9. Input sanitize (ASCII keyboard default)

**Status:** engine + modular pager adapter wired (paste/submit/interject/send-now/bash/
headless text+JSON + slash passthrough). Pending paste strip report re-attaches model
notes on submit. Residual-risk **analysis** (statistical / steganographic / phrase
heuristics) runs after the mechanical pass. Permanent config write for `--user`/`--project`
still TBD (session allow works).

### Goal

Reduce prompt-injection and spoofing that relies on **invisible or deceptive Unicode**
(zero-width, bidi controls, math lookalike letters, emoji smuggling) while keeping
normal English keyboard input seamless.

**Also flag** residual risk on *cleaned* text: pure-ASCII jailbreaks, encoded blobs,
whitespace bit-channels, ZW interleave transforms, and strip-reveals-payload patterns.
Mechanical filtering alone can leave a new, harmless-looking prompt that is still an
attack “under the eyes” of the user.

Analysis is heuristic (not a trained classifier). Still need sandbox, permissions, and
user judgment for novel attacks.

### Default allowlist

| Keep | Hex |
|------|-----|
| Printable ASCII (US keyboard) | `U+0020`–`U+007E` |
| Newline | `U+000A` (LF); `U+000D` (CR) normalized to LF |

Everything else is classified and **stripped by default**.

### Category switch table (opt-in extensions)

| Category | Severity | Default | User may `/input-allow`? |
|----------|----------|---------|---------------------------|
| `tab` | capability | strip | yes |
| `latin_extended` | capability | strip | yes |
| `unicode_letters` | capability | strip | yes |
| `unicode_punctuation` | capability | strip | yes |
| `emoji` | capability | strip | yes |
| `math_symbols` | capability | strip | yes |
| `math_alphanumeric` | security | strip | **no** (lookalike Latin) |
| `zero_width_format` | security | strip | **no** |
| `bidi_controls` | security | strip | **no** |
| `control_c0_c1` | security | strip | **no** |
| `private_use` | security | strip | **no** |
| `noncharacters` | security | strip | **no** |

Actions: `strip` | `keep` | `reject`.

### Runtime behavior (target UX)

1. On paste/submit: sanitize → cleaned text → **analyze** residual risk.
2. If any category fired **or** analysis ≥ medium: model gets `<input_sanitize>…</input_sanitize>` note.
3. **Security hits:** model must **warn the user** (invisible/deceptive chars; possible injection).
4. **Analysis elevated:** model must warn that cleaned text may still be an attack; confirm intent.
5. **Capability hits:** model may suggest `/input-allow <cat> --session|--user|--project`.
6. User enables extensions via command (session or permanent config). Model cannot self-enable.

### Residual-risk analysis (post-filter)

| Signal | What it catches |
|--------|-----------------|
| `security_carrier_density` | High ratio of ZW/bidi/lookalike carriers |
| `strip_reveals_payload` | Heavy strip still leaves a long alphabetic message |
| `zero_width_interleave` | ZW/bidi between letters (stego channel) |
| `whitespace_bit_channel` | 1- vs 2-space run patterns |
| `dual_channel_divergence` | Visible-ish projection ≠ cleaned structure |
| `high_entropy_cleaned` | Shannon entropy in packed/encoded band |
| `encoded_blob` | Long base64/hex spans |
| `injection_phrase` | Classic jailbreak / override phrases on cleaned ASCII |
| `role_override_density` | Clusters of instruction-control markers |
| `char_distribution_anomaly` | χ² vs English letter baseline |
| `symbol_digit_skew` | Digit/symbol-heavy “prose” |

Score 0–100 → level none/low/medium/high/critical. Medium+ attaches model note + toast.

### Config sketch (not yet wired)

```toml
[input_sanitize]
enabled = true
notify_when_stripped = true
analyze = true
tab = "strip"
latin_extended = "strip"
emoji = "strip"
# … all categories default strip
```

### Crate

- `crates/codegen/xai-grok-input-sanitize` — `sanitize()` + `analyze` + `format_model_note()`
- Tests: `cargo test -p xai-grok-input-sanitize`

---

## 10. Change log (hardening fork)

| Date | Change |
|------|--------|
| 2026-07-15 | Phase 0: DNS-pin SSRF, expanded dangerous commands, `deny.toml`, sandbox example |
| 2026-07-16 | Phase 1 input sanitize: `xai-grok-input-sanitize` engine (ASCII default + categories) |
| 2026-07-16 | Modular wire-up: paste/submit/headless sanitize, model note, `/input-allow` session |
| 2026-07-16 | Adversarial harden: pending paste notes, interject/bash/JSON gates, filler→security, fail-closed headless reject |
| 2026-07-16 | Residual-risk analysis: statistical/stego/phrase signals on cleaned text + strip transform |

---

## 11. References (in-tree)

- `crates/codegen/xai-grok-input-sanitize/src/lib.rs`
- `crates/codegen/xai-grok-pager/docs/user-guide/18-sandbox.md`
- `crates/codegen/xai-grok-pager/docs/user-guide/22-permissions-and-safety.md`
- `crates/codegen/xai-grok-sandbox/src/lib.rs`
- `crates/codegen/xai-grok-tools/src/implementations/grok_build/web_fetch/ssrf.rs`
- `crates/codegen/xai-grok-workspace/src/permission/{manager,shell_access,policy}.rs`
- `SECURITY.md` (upstream HackerOne)

---

## MCP note

WIP hard-disable of MCP lives on the **`no-mcp`** branch only. **`main`** still
contains upstream MCP code. See that branch before merging MCP changes.
