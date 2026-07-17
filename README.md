<div align="center">

<h1>
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://media.x.ai/v1/website/spacexai-symbol-white-transparent-0c31957f.png">
    <source media="(prefers-color-scheme: light)" srcset="https://media.x.ai/v1/website/spacexai-symbol-black-transparent-6435cf42.png">
    <img alt="SpaceXAI logo" src="https://media.x.ai/v1/website/spacexai-symbol-black-transparent-6435cf42.png" width="96">
  </picture>
  <br>
  Grok Build (<code>grok</code>) — opinionated fork
</h1>

**Grok Build** is SpaceXAI's terminal-based AI coding agent. It runs as a
full-screen TUI that understands your codebase, edits files, executes shell
commands, searches the web, and manages long-running tasks — interactively,
headlessly for scripting/CI, or embedded in editors via the Agent Client
Protocol (ACP).

[About this fork](#about-this-fork) ·
[Installing the released binary](#installing-the-released-binary) ·
[Building from source](#building-from-source) ·
[Documentation](#documentation) ·
[Repository layout](#repository-layout) ·
[Development](#development) ·
[Contributing](#contributing) ·
[License](#license)

![Grok Build TUI](https://media.x.ai/v1/website/universe-tui-screenshot-6f7a0837.png)

**Official product:** [x.ai/cli](https://x.ai/cli) · **Upstream source:** SpaceXAI’s
periodically published Grok Build tree (Apache-2.0; external PRs not accepted
upstream)

</div>

---

## About this fork

This repository is an **independent, opinionated fork** of SpaceXAI’s open-sourced
Grok Build CLI/TUI. The goal is **slightly more robust defaults and defense in
depth** for local agent use — not a certified, “hardened,” or production-safe
product.

> [!WARNING]
> **This is not “safe.”** An agent that can run shell, edit files, and talk to the
> network remains a high-risk tool. Changes here only reduce some classes of
> prompt-injection and spoofing noise, close a few known gaps, and make policy a
> bit more explicit. They do **not** make untrusted repos, malicious MCP servers,
> bypass modes, or sandbox-off workflows safe. Treat the agent as capable of
> full local compromise under bad inputs or bad config.

Upstream already ships substantial permission, sandbox, and SSRF work. This fork
adds incremental layers on top; details and remaining gaps live in
[`HARDENING.md`](HARDENING.md).

### What was done here (high level)

| Area | Change (summary) |
|------|------------------|
| **Input / Unicode** | Terminal paste/submit sanitizer with profiles (strict / balanced / multilingual / custom), settings UI + `/input-filter`, residual-risk notes for the model; mid-stack filter for untrusted tools/skills/AGENTS/hooks; **model-bound hard strip** on sampling egress (invisibles, lookalikes, exotic emoji) |
| **Network** | DNS-pin style SSRF fix path for `web_fetch` (resolve once, connect to allowed addrs) — see hardening notes |
| **Shell policy** | Expanded dangerous-command coverage (partial) so more high-risk programs fail auto-allow |
| **Supply chain / process** | `deny.toml` scaffolding; threat model + gap list in `HARDENING.md` |
| **Examples** | Hardened sandbox profile / launch guidance for people who opt in |

What this fork **does not** claim: sandbox on by default, verified auto-updates,
full MCP/plugin trust, OS-level isolation you did not enable, or any guarantee
against prompt injection succeeding.

Recommended reading: [`HARDENING.md`](HARDENING.md) (threat model, findings,
recommended flags). For daily use on a trusted machine, prefer opting into
sandbox (`--sandbox workspace` or stricter) rather than assuming this tree is
safer by name alone.

### Naming

The repo path may still say `grok-build-hardened`. That name oversells the work;
treat it as a historical label, not a security claim.

---

## Installing the released binary

> Official **prebuilt** installers below install **upstream SpaceXAI** binaries,
> not this fork. To run *this* tree, [build from source](#building-from-source).

Prebuilt binaries are published for macOS, Linux, and Windows:

```sh
curl -fsSL https://x.ai/cli/install.sh | bash   # macOS / Linux / Git Bash
irm https://x.ai/cli/install.ps1 | iex          # Windows PowerShell
grok --version
```

See the [changelog](https://x.ai/build/changelog) for the latest fixes,
features, and improvements in each **upstream** release.

## Building from source

Requirements:

- **Rust** — the toolchain is pinned by [`rust-toolchain.toml`](rust-toolchain.toml);
  `rustup` installs it automatically on first build.
- **protoc** — proto codegen resolves [`bin/protoc`](bin/protoc) (a
  [dotslash](https://dotslash-cli.com) launcher) or falls back to a `protoc` on
  `PATH` / `$PROTOC`.
- macOS and Linux are supported build hosts; Windows builds are best-effort
  and not currently tested from this tree.

```sh
cargo run -p xai-grok-pager-bin              # build + launch the TUI
cargo build -p xai-grok-pager-bin --release  # release binary: target/release/xai-grok-pager
cargo check -p xai-grok-pager-bin            # fast validation
```

The binary artifact is named `xai-grok-pager`; official installs ship it as
`grok`. On first launch it opens your browser to authenticate — see the
[authentication guide](crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md).

## Documentation

Full online documentation for the **upstream** product is at
[docs.x.ai/build/overview](https://docs.x.ai/build/overview).

Fork-specific security notes and roadmap:
[`HARDENING.md`](HARDENING.md).

The user guide ships with the pager crate:
[`crates/codegen/xai-grok-pager/docs/user-guide/`](crates/codegen/xai-grok-pager/docs/user-guide/)
— getting started, keyboard shortcuts, slash commands, configuration, theming,
MCP servers, skills, plugins, hooks, headless mode, sandboxing, and more.

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

This is a personal/maintainer fork, not SpaceXAI’s contribution channel. See
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
