# rbw for Windows

This branch is a port of [rbw](https://github.com/doy/rbw) 1.15.0 (the unofficial Bitwarden / Vaultwarden command line client
with a background agent) to native Windows. Upstream supports Unix only. All credit for rbw goes to Jesse Luehrs and its
contributors; this port changes only what Windows needs. It is MIT licensed like upstream (see `LICENSE`) and is not
affiliated with or endorsed by upstream or Bitwarden.

## What works

`rbw.exe` and `rbw-agent.exe` build with a stock Rust toolchain on Windows 10/11 (x64). The agent starts on demand, stays
resident, and the client talks to it over a per-user named pipe, so repeated lookups are fast (about 0.1-0.2 s per call
instead of seconds with the official Node-based CLI). Verified by the author: the agent starts on demand, answers the client over the pipe, locks and stops cleanly; register, login, unlock,
sync and reading entries against a Bitwarden EU account; the crate's unit tests (`cargo test`). Reading against a self-hosted Vaultwarden
is being confirmed. The Unix code paths are kept behind `cfg(unix)` but were not compiled by the author; the CI of this repository is the check.

Not verified: every 2FA method (FIDO2/WebAuthn is not supported by rbw upstream either), editing and creating entries,
`rbw code`, the clipboard commands, notifications/websocket sync over long periods, and Windows on ARM.

## What differs from upstream

| Area | Unix | This port |
|---|---|---|
| Agent IPC | unix domain socket in the runtime dir | named pipe `\\.\pipe\<profile>-<USERNAME>-agent` |
| Pipe access | socket in a `0700` directory | owner = you; protected DACL with one ACE (full control for your SID only); the first pipe instance must be new; remote clients rejected; the client refuses a pipe not owned by you and forbids server impersonation |
| Starting the agent | `daemonize` (fork) | the client re-launches `rbw-agent.exe --no-daemonize` detached (`CreateProcessW`, handle inheritance off) and waits for the pipe |
| One agent per profile | pidfile lock | pidfile opened with an exclusive share mode |
| ssh-agent | built in | not available on Windows |
| Debugger / core-dump hardening | prctl, ptrace, rlimit | not available (the agent logs a warning at start); memory locking works |
| Vault cache file name | `server:email.json` | `server;email.json` (`:` would create an NTFS alternate data stream) |
| Config and data | XDG-style dirs | `~/.config/<profile>` (`$XDG_CONFIG_HOME`), `~/.local/cache/<profile>` (`$XDG_CACHE_HOME`), `~/.local/share/<profile>` (`$XDG_DATA_HOME`); `<profile>` is `rbw` for the default profile, `rbw-<name>` for `RBW_PROFILE=<name>`. Nothing is written to AppData. Note the cache default is `~/.local/cache`, not the XDG spec's `~/.cache` |

Any process running as your user can still talk to the agent, exactly as with upstream's private unix socket.

## Install

1. Download the zip from the releases page, check its SHA-256 against the `.sha256` file, unzip somewhere (for example
   `%LOCALAPPDATA%\Programs\rbw`).
2. Put that folder on `PATH`, **or** call `rbw.exe` by full path and set `RBW_AGENT` to the full path of `rbw-agent.exe`.
3. rbw asks for passwords through a `pinentry` program (Assuan protocol). On Windows use `pinentry-w32` (ships with Git for
   Windows and Gpg4win) or any compatible program: `rbw config set pinentry <path-to-pinentry.exe>`.
4. Configure and log in:

```powershell
rbw config set email you@example.com
rbw config set base_url https://vault.example.com      # your Vaultwarden; for Bitwarden EU: https://vault.bitwarden.eu
rbw register      # official Bitwarden servers only: asks for your API client_id and client_secret
rbw login
rbw unlock
rbw list
```

`RBW_PROFILE=<name>` keeps separate configurations, vaults and agents side by side.

## Build from source

```powershell
cargo build --release     # needs the Rust toolchain (https://rustup.rs) and a C++ linker (Visual Studio Build Tools)
```

## Notes for maintainers

The port is a small patch on top of an upstream release tag (`git diff <tag>..windows`). New upstream releases are merged or
rebased onto this branch; releases here are tagged `<upstream version>-windows.<n>`.
