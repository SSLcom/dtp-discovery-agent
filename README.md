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

Which puts the whole weight on the key staying where it was put. It is written
`0600` in a `0700` directory, and **tightened on every open** rather than only at
creation — a key restored from a backup or laid down by a configuration tool
arrives with whatever permissions it arrives with. On **Windows**, where there
are no mode bits and `os.Chmod` succeeds without changing who may read anything,
the same intent is an ACL: full control for this agent, SYSTEM and the
administrators, and **inheritance broken**, so the read access `%ProgramData%`
hands to every local user by default stops applying.

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

**A file of nothing but CA certificates is skipped.** That is a *trust store* —
`ca-certificates.crt`, a chain file on its own — and it is a list of the issuers
a machine is willing to believe, not something deployed on it. Measured on an
ordinary host, reporting one meant a CA root nobody chose arriving with a
hundred and twenty others as its "chain", from every machine in an estate. The
end-entity certificate is also located by *looking* for it rather than taking
the first in the file, because bundles are concatenations and plenty of tools
write the chain first.

### Java keystores (`java_keystore`)

**Invisible to every other collector.** A `.jks` is neither PEM nor DER, so a
filesystem walk reads straight past it — which means a Tomcat, a JBoss or an
Elasticsearch terminating TLS looks, to every other source, like a machine with
no certificates on it at all.

JKS and JCEKS are read directly rather than through a library, for two reasons
that are the same reason. **The private keys are never read**: a key entry
carries its encrypted blob behind a length, and the parser skips that many bytes
without looking at them, so the bytes are never copied, decrypted or held. A
keystore library exists to return keys; this does not. And it follows that **the
agent needs no password** — certificate entries in a JKS are not encrypted, so
the certificates come out of a store whose password nobody has told the agent,
which is the usual situation on a machine set up years ago by somebody who left.

Findings are per *alias*, because the alias is what `keytool -delete -alias`
takes and, on a store with six of them, the only thing that says which one is
expiring. A `cacerts` contributes nothing, by the trust-store rule above.

PKCS#12 keystores — what `keytool` has written by default since JDK 9 — are read
too, when they open with an empty password.

### The operating system's own store (`os_store`)

**On Windows a certificate does not live in a file.** IIS, SQL Server, RDP and
WinRM all bind to a store entry, so there is no PEM on the disk for a
file-walking collector to find — every other source reports a Windows web server
as a machine with no certificates on it. Read through `crypt32` directly, with no
cgo, opening each store read-only.

On macOS the system keychain, read through `/usr/bin/security`. A subprocess is
not this agent's habit; the alternatives are cgo, which would end the single
portable static binary, or parsing an undocumented file format.

Both report **whether this machine holds the private key**, which is the only
thing separating a certificate a service can serve from one somebody imported to
trust — on Windows they sit in the same kind of store. The hundreds of trust
anchors that come back with them are dropped by the same rule that drops a
`cacerts`.

Linux has no such store. `/etc/ssl/certs` is files, which the filesystem
collector already reads; reporting them again here would give a member two rows
to reconcile for one certificate.

### IIS (`server_config`)

IIS keeps a site's certificate **nowhere near its configuration**, and that
shapes the whole implementation. `applicationHost.config` lists the sites and
their bindings and stops there; the certificate a binding presents is held by
HTTP.sys, in the registry, as a thumbprint into a certificate store. So a site's
certificate is three things joined — the configuration file for its *name*, the
registry for its *thumbprint*, and the store for the certificate itself.

The most specific binding is looked up first. On a host with twenty sites behind
one address the address-only entry is the *fallback* certificate, and reaching
for it first would report all twenty sites as serving it while the nineteen real
certificates stayed invisible — the same failure as probing a listener without
SNI.

An https binding HTTP.sys has no certificate for is **reported**: that is not
the agent failing to look, it is a site that will not serve.

### Web server configuration (`server_config`)

**The only source that knows which *site* a certificate belongs to.** The file
collector can say a certificate is at `/etc/ssl/site.pem`; only the
configuration says it is what `www.example.com` presents, that the key is the
file two directories away, and that a second certificate is configured beside it
for clients that cannot do ECDSA. It also finds certificates nothing else does —
a path outside every scanned root is still found, because the configuration
named it.

nginx and Apache today. Includes are followed and spliced in place, because on a
Debian host `sites-enabled` *is* the configuration; Apache's are resolved against
`ServerRoot` rather than the including file, which is the difference between
reading a Red Hat host's sites and reading none of them.

**A configured certificate that is missing is a finding, not a failure** — the
site is broken, or will be at the next reload — so it is reported. Whether it
stops the sweep counting as complete turns on *why*: a file that is **gone** was
seen clearly and its placement should be retired, while one that could not be
**read** is a certificate the agent did not see, and must never be reported as
one that was removed.

IIS is not here yet. `applicationHost.config` names only a thumbprint; the
certificate itself lives in the Windows store, so IIS waits for the `os_store`
collector rather than producing sites with no certificate to report.

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

It probes once carrying no SNI and once per name it is given. A name that draws
no certificate is ordinary — not every name on a machine is on every socket — so
it stops that name, not the sweep; and a port that refuses the *nameless* probe
is still asked for its names, because nginx's `ssl_reject_handshake` does
exactly that while serving every named site perfectly.

Ports that serve something other than TLS are silent, not errors: a host is full
of them. A listener the agent could *not* finish talking to is reported and
stops the sweep counting as complete, because a certificate it could not see is
not one that was removed.

On Windows and macOS the agent cannot yet read the socket table, so it probes a
well-known port list instead — and, because a guess is not a sweep, never
declares this source complete there.

It is told the server names the configuration collector found and sends each as
SNI. That ordering is load-bearing: a probe carrying no SNI gets a name-based
virtual host's **default** certificate, so on a machine hosting twenty sites the
other nineteen are invisible — and they are exactly the ones nobody is watching.

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

**Rebuild from a checkout that HAS the tag**, which `git checkout v1.2.3` above
gives you but `git clone --depth 1` of a branch does not. Go stamps the main
module's own version into the binary, and it derives that from the nearest
reachable git tag: with the tag present you get `v1.2.3`, without it
`v0.0.0-<date>-<commit>`, and the binaries differ by exactly that string. Same
source, same compiler, different bytes — which looks like tampering and is not.
It is the one way to get a mismatch while doing everything else right.

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

Collectors shipped: filesystem, Java keystores, the Windows certificate store
and macOS keychain, nginx and Apache configuration, IIS, and the local TLS
listener probe.

**NSS databases are deliberately not collected.** Reading `cert9.db` means either
a SQLite dependency several times the size of this binary, or shelling out to
`certutil`, which is not installed on the machines that would have one. The
technology it serves on a server — `mod_nss` — has been superseded by `mod_ssl`,
and a Firefox profile is not a certificate deployment. It is listed here rather
than left unsaid: if an estate turns out to need it, the cost is known.

Packaging shipped: tarballs and zips for six platforms, `.deb` and `.rpm`,
systemd units and a launchd plist. Not yet: an `.msi` and a Windows Service
wrapper (which needs the binary to speak the service control protocol), and a
Homebrew tap.

## License

MIT.
