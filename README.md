# dtp-discovery-agent

The certificate **discovery agent** for the Digital Trust Platform: a single
static binary a member installs on their own servers. It inventories every
certificate it can find and reports what it found to DTP, so an account can
answer the question DTP could not answer before — *what certificates are
installed on my machines, and which of them are about to break something?*

The server half is the `dtp-discovery` engine inside the Digital Trust Platform, which is not public.

## Two properties everything else follows from

**This agent holds its own key, and DTP never sees it.** It generates a P-256
keypair on first run and sends only the public half; every later request is
authenticated by a detached signature over an assertion. DTP stores no secret
for this agent, so revoking it is a status flip on the server rather than a
rotation here, and a dump of the server's tables grants nobody anything.

**It never transmits private key material.** That is enforced three times over,
because it is the one failure that cannot be walked back:

1. `collect.Observation` has no field for key bytes. The agent records *that* a
   key sits beside a certificate and *where* — an operator needs to know a key
   exists and is mode 0644 — but the bytes are never read into the struct.
2. `parse` re-encodes certificates from their parsed DER rather than slicing
   bytes out of the file, so a combined key+certificate file (the haproxy
   layout) yields the certificate and nothing else.
3. `transport` runs every outbound body past a guard and refuses locally. It
   should never fire; the server refuses such a payload too, but by then it has
   crossed the network.

## Commands

```
dtp-agent enroll --server URL --account ID [--token TOKEN] [--root DIR] [--without SOURCE]
dtp-agent scan [--root DIR] [--without SOURCE] [--json]   # print, upload nothing
dtp-agent run [--once] [--root DIR] [--without SOURCE]   # scan and upload
dtp-agent status                         # what this agent is and last did
dtp-agent version
```

`scan` is the one to reach for first: it shows exactly what the agent *would*
report without letting it report anything.

**Enrolling waits, it does not fail.** An agent lands `pending` and a member
holding `discovery:registrations:approve` admits it. Running the installer
before anyone has clicked approve is the normal case in a rollout, so `run`
waits and retries; `--once` is for a cron job that should not hold a process
open.

## What it scans

### Files (`file`)

Bounded by default, because this runs unattended on machines nobody is
watching. The defaults cover the usual TLS locations (`/etc/ssl`, `/etc/pki`,
`/etc/nginx`, `/etc/letsencrypt`, …), cap files at 1 MiB and depth at 8, do not
follow symlinks, and only open files whose extension suggests a certificate.
A host with an unusual layout adds `--root` rather than the agent widening its
sweep — an agent that walks `/` on a machine with an NFS mount is the incident
this product exists to prevent.

Recognised today: PEM and DER certificate files, and PKCS#12 bundles with an
empty password. The agent never guesses at a password.

### Local TLS listeners (`listener`)

**This is the only source that reports what is actually being served**, and the
difference is the whole point: a certificate renewed into `/etc/ssl` an hour ago
protects nobody if nothing reloaded, and every other source calls that host
healthy.

The agent reads its own listening sockets from `/proc/net/tcp` and
`/proc/net/tcp6`, opens a TLS connection to each, takes the certificate and
closes it. **It sends no application data — not a byte.** A probe that spoke the
application protocol to whatever answered would be a scanner, not an inventory.

Three things it deliberately does:

- **Accepts certificates no client would.** Expired, self-signed, issued for
  another name: those are the findings. Verifying would discard them.
- **Reports the certificate of a listener that refuses it.** A mutually
  authenticated service rejects the agent for having no client certificate — but
  by then it has presented its own, and that expiry is a fact an operator needs
  whether or not the agent was let in.
- **Speaks down to TLS 1.0.** Forgotten listeners are old listeners.

Ports that serve something other than TLS are silent, not errors: a host is full
of them. A listener the agent could *not* finish talking to is reported and
stops the sweep counting as complete, because a certificate it could not see is
not one that was removed.

On Windows and macOS the agent cannot yet read the socket table, so it probes a
well-known port list instead — and, because a guess is not a sweep, never
declares this source complete there.

**Turning it off:** `--without listener`, at enrolment (recorded in the config)
or on a single `scan`/`run`. Probing local services is a thing a security team
may reasonably forbid. A disabled source is never declared complete, so turning
one off makes its past findings go stale rather than making them disappear.

## The protocol, and the two fields that fail silently

**[`docs/PROTOCOL.md`](docs/PROTOCOL.md)** describes the whole wire protocol —
every endpoint, the assertion construction, the status codes and what they mean,
the rate limits, and the versioning promise. Enough to audit what this agent
sends, or to write your own client.

Two client obligations are worth repeating here, because dropping either changes
behaviour and raises no error:

- **`X-DTP-Agent-Fingerprint` on `/discovery/v1/token`.** Nothing on the server
  reads it; the host's rate limiter does, because middleware cannot parse a
  JSON body. An agent that omits it still authenticates and joins the shared
  per-IP bucket with every other agent behind the same address — which, for a
  fleet inside one customer's network, is all of them.
- **`completed_sources` on the final inventory page.** It names the collectors
  that finished cleanly, and it is the only thing that lets DTP conclude a
  certificate is no longer deployed. A collector that hit a permission error saw
  certificates it *could not see*, not certificates that were removed, so it is
  omitted — and the failure mode of omitting it is an inventory that never
  shrinks rather than certificates that wrongly vanish.

Both are asserted in `internal/transport`, and a test checks the protocol
document still says what the code does — a constant that drifts there does not
break a build, it breaks somebody else's client for reasons they cannot see.

## Installing

```sh
curl -fsSL https://raw.githubusercontent.com/SSLcom/dtp-discovery-agent/main/install.sh | sh
```

**The installer verifies the checksum and refuses to proceed without one.** If
`SHA256SUMS` cannot be fetched, does not list your archive, or does not match,
nothing is installed. It is on GitHub so you can read it before running it —
and if piping a script into a shell is not for you, the manual path is below and
is what the script does anyway.

On Debian/Ubuntu or RHEL/Fedora, prefer the package: it places the systemd units
and survives upgrades.

```sh
# Verify, then install.
curl -fsSLO https://github.com/SSLcom/dtp-discovery-agent/releases/latest/download/SHA256SUMS
curl -fsSLO https://github.com/SSLcom/dtp-discovery-agent/releases/latest/download/dtp-agent_VERSION_amd64.deb
sha256sum -c --ignore-missing SHA256SUMS
sudo dpkg -i dtp-agent_VERSION_amd64.deb
```

Installing is not enrolling: the package leaves the timer **stopped**, because
the agent has no account or token until you give it one.

```sh
sudo dtp-agent enroll --server https://YOUR-DTP --account YOUR-ACCOUNT-ID --token dtpd_...
sudo systemctl enable --now dtp-agent.timer
```

The timer runs hourly with a randomised delay of up to fifteen minutes, so a
fleet installed from one image does not arrive at DTP all at once. The service
unit runs the scan at idle IO and CPU priority under `ProtectSystem=strict`,
with the state directory as its only writable path.

**Every release is reproducible.** The archives are built with `-trimpath`,
sorted entries and a fixed mtime, so you can rebuild a tag yourself and compare:

```sh
git checkout v1.2.3 && script/build-release.sh 1.2.3 && cat dist/SHA256SUMS
```

CI enforces this by building twice and diffing, and it holds across machines —
a local rebuild of v0.1.0 matched the published archives byte for byte.
Rebuilding the tag yourself is the verification path that depends on trusting
nobody.

Releases **after v0.1.0** also carry a GitHub build-provenance attestation — a
signed statement of which workflow, from which commit, produced those exact
bytes:

```sh
gh attestation verify dtp-agent_1.2.3_linux_amd64.tar.gz --repo SSLcom/dtp-discovery-agent
```

v0.1.0 has none: the repository was private when it was cut, and
`actions/attest-build-provenance` is unavailable to private repositories on this
plan. Its checksums and reproducible build stand on their own.

## Releasing

```sh
git tag -a v1.2.3 -m "…" && git push origin v1.2.3
```

The workflow is a thin wrapper over scripts that run identically on a laptop, so
the release path is exercised on every change rather than only when a tag is
pushed:

```sh
script/build-release.sh 1.2.3    # archives + checksums for all six targets
script/build-packages.sh 1.2.3   # .deb and .rpm, via a digest-pinned nfpm image
script/test-install.sh 1.2.3     # install.sh accepts what it should, refuses what it should not
```

## Development

```sh
go test ./...
go vet ./...
go build -ldflags "-X main.Version=$(git describe --tags --always)" ./cmd/dtp-agent
```

Against a local DTP:

```sh
dtp-agent enroll --server http://localhost:3000 --account <uuid> --token dtpd_… \
  --root ./testdata --state /tmp/agent-state
dtp-agent run --once --state /tmp/agent-state
```

## Status

**v1 is read-only.** No write path is compiled in. Installing certificates,
generating a CSR on the host, and the command queue are v2 — designed for in
the server's `AgentCommand` shape, not built.

Collectors shipped: filesystem, local TLS listener probe. Planned:
nginx/Apache/IIS config parsing, OS and application trust stores (Windows store,
macOS keychain, NSS, Java keystores).

The listener probe sends SNI for any name it is given, which is how the other
twenty sites on a name-based virtual host become visible — a probe without SNI
gets only the default certificate. Nothing supplies those names yet; the
server-config collector is what will.

Packaging shipped: tarballs and zips for six platforms, `.deb` and `.rpm`,
systemd units and a launchd plist. Not yet: an `.msi` and a Windows Service
wrapper (which needs the binary to speak the service control protocol), and a
Homebrew tap.

## License

MIT.
