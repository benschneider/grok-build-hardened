# Grok Build fork (`grok`) — opinionated, slightly more robust

> [!IMPORTANT]
> **Not affiliated with xAI / SpaceXAI.** This is an independent personal fork.
> It is not an official product, release channel, or support surface. Upstream
> trademarks and product names remain theirs.

[Grok Build](https://x.ai/cli) is SpaceXAI’s terminal-based AI coding agent (TUI,
headless, ACP). SpaceXAI periodically publishes source under Apache-2.0 for
transparency. **This repository** takes that published tree and adds a few
opinionated defenses — nothing more.

**Goal:** slightly more robust local use (input filtering, a few closed gaps).
**Not a goal:** “safe,” certified, enterprise-hardened, or drop-in official
support.

[About this fork](#about-this-fork) ·
[Build from source](#build-from-source) ·
[Documentation](#documentation) ·
[Repository layout](#repository-layout) ·
[Development](#development) ·
[Contributing](#contributing) ·
[License](#license)

---

## About this fork

Upstream already invests in permissions, sandbox, and SSRF. This fork adds
incremental layers on top. Details and remaining gaps:
[`HARDENING.md`](HARDENING.md).

> [!WARNING]
> **This is not “safe.”** An agent that can run shell, edit files, and use the
> network remains high-risk. Changes here only reduce some prompt-injection /
> spoofing noise and make a few policies more explicit. They do **not** make
> untrusted repos, malicious MCP servers, bypass modes, or sandbox-off
> workflows safe. Assume full local compromise is possible under bad inputs or
> bad config.

### What was done here (high level)

| Area | Change (summary) |
|------|------------------|
| **Input / Unicode** | Terminal paste/submit sanitizer with profiles (strict / balanced / multilingual / custom), settings UI + `/input-filter`, residual-risk notes for the model; mid-stack filter for untrusted tools/skills/AGENTS/hooks; **model-bound hard strip** on sampling egress (invisibles, lookalikes, exotic emoji) |
| **Network** | DNS-pin style SSRF path for `web_fetch` (resolve once, connect to allowed addrs) — see hardening notes |
| **Shell policy** | Expanded dangerous-command coverage (partial) so more high-risk programs fail auto-allow |
| **Supply chain / process** | `deny.toml` scaffolding; threat model + gap list in `HARDENING.md` |
| **Examples** | Opt-in sandbox profile / launch guidance |

What this fork **does not** claim: sandbox on by default, verified auto-updates,
full MCP/plugin trust, OS isolation you did not enable, or any guarantee against
prompt injection.

Prefer opting into sandbox (`--sandbox workspace` or stricter) rather than
trusting any name that sounds security-related. This repo is intentionally
named as a **personal fork** (e.g. `grok-build-fork-ben`), not a hardened product.

---

## Build from source

This is how you run **this** fork. There is no official fork binary channel.

Requirements:

- **Rust** — toolchain pinned by [`rust-toolchain.toml`](rust-toolchain.toml);
  `rustup` installs it on first build.
- **protoc** — resolves [`bin/protoc`](bin/protoc) (a
  [dotslash](https://dotslash-cli.com) launcher) or a `protoc` on `PATH` /
  `$PROTOC`.
- macOS and Linux are supported build hosts; Windows is best-effort from this
  tree.

```sh
cargo run -p xai-grok-pager-bin              # build + launch the TUI
cargo build -p xai-grok-pager-bin --release  # target/release/xai-grok-pager
cargo check -p xai-grok-pager-bin            # fast validation
```

The binary artifact is named `xai-grok-pager` (upstream installs often ship it as
`grok`). Auth and API behavior still go through SpaceXAI’s product paths —
this fork does not replace their service.

In-tree auth notes:
[authentication guide](crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md).

### Upstream installers (not this fork)

Prebuilt installers from x.ai install **SpaceXAI’s** binaries, not this tree:

```sh
curl -fsSL https://x.ai/cli/install.sh | bash   # macOS / Linux / Git Bash
irm https://x.ai/cli/install.ps1 | iex          # Windows PowerShell
```

Upstream product: [x.ai/cli](https://x.ai/cli) ·
[changelog](https://x.ai/build/changelog) ·
[docs](https://docs.x.ai/build/overview)

---

## Documentation

| Doc | What |
|-----|------|
| [`HARDENING.md`](HARDENING.md) | Fork threat model, findings, roadmap |
| [Upstream docs](https://docs.x.ai/build/overview) | Official product documentation |
| [`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/) | In-tree user guide (shortcuts, config, MCP, sandbox, …) |

---

## Repository layout

| Path | Contents |
|------|----------|
| `crates/codegen/xai-grok-pager-bin` | Composition-root package; builds the `xai-grok-pager` binary |
| `crates/codegen/xai-grok-pager` | The TUI: scrollback, prompt, modals, rendering |
| `crates/codegen/xai-grok-shell` | Agent runtime + leader/stdio/headless entry points |
| `crates/codegen/xai-grok-tools` | Tool implementations (terminal, file edit, search, ...) |
| `crates/codegen/xai-grok-workspace` | Host filesystem, VCS, execution, checkpoints |
| `crates/codegen/...` | The rest of the CLI crate closure (config, MCP, markdown, sandbox, ...) |
| `crates/common/`, `crates/build/`, `prod/mc/` | Small shared leaf crates pulled in by the closure |
| `third_party/` | Vendored upstream source (Mermaid diagram stack) — see below |

> [!IMPORTANT]
> The root `Cargo.toml` (workspace members, dependency versions, lints,
> profiles) is **generated** — treat it as read-only. Prefer editing per-crate
> `Cargo.toml` files.

## Development

```sh
cargo check -p <crate>        # always target specific crates; full-workspace builds are slow
cargo test -p xai-grok-config # per-crate tests
cargo clippy -p <crate>       # lint config: clippy.toml at the repo root
cargo fmt --all               # rustfmt.toml at the repo root
```

## Contributing

Unaffiliated personal fork — not SpaceXAI’s contribution channel. See
[`CONTRIBUTING.md`](CONTRIBUTING.md).

## License

First-party code in this repository is licensed under the **Apache License,
Version 2.0** — see [`LICENSE`](LICENSE).

Third-party and vendored code remains under its original licenses. See:

- [`THIRD-PARTY-NOTICES`](THIRD-PARTY-NOTICES) — crates.io / git dependencies,
  bundled UI themes, and **in-tree source ports** (including openai/codex and
  sst/opencode tool implementations)
- [`crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md`](crates/codegen/xai-grok-tools/THIRD_PARTY_NOTICES.md)
  — crate-local notice for the codex and opencode ports (license texts +
  Apache §4(b) change notice)
- [`third_party/NOTICE`](third_party/NOTICE) — vendored Mermaid-stack index
