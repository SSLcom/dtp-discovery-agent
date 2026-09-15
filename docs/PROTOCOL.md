# The DTP discovery agent protocol

What `dtp-agent` sends, what DTP sends back, and why each piece is shaped the
way it is. Enough to audit the agent's behaviour, to write your own client, or
to decide whether you want this software on your servers.

Everything below is `v1`, served under `/discovery/v1` on your DTP instance.

---

## The two properties everything else follows from

**The agent holds its own key, and DTP never sees it.** The agent generates a
P-256 keypair on first run and sends only the public half. Every authenticated
request rests on a signature over an assertion, so DTP stores no secret
belonging to an agent: a dump of its tables grants nobody anything, and
revoking an agent is a status change rather than a key rotation.

**A person approves each binding.** An agent does not join an account by
claiming one. It *requests* to, and a member holding the `approve` permission
admits it. Until then it is owned by nobody and can do nothing. An enrollment
token with pre-approval does not bypass this — it moves the decision earlier,
and records the person who minted the token as the approver.

Everything is **agent-initiated**. There is no push channel and no inbound
connection to your host; the agent calls out, or nothing happens.

---

## The shape of a session

```
  register  ─────────────────────────────►  lands pending, owned by nobody
                                                    │
                                            a person approves
                                                    │
  token     ◄──── 202 while pending ────────────────┘
            ─────────────────────────────►  ~15-minute bearer

  checkin   ─────────────────────────────►  heartbeat + server clock
  inventory ─────────────────────────────►  what the scan found, paged
```

`register` happens once per host. `token` happens whenever the bearer has
expired. `checkin` and `inventory` need the bearer.

---

## `POST /discovery/v1/register`

Unauthenticated, necessarily — the agent has no credential yet, and asking for
one is the point.

```json
{
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n…",
  "account_id": "<uuid of the DTP account to join>",
  "enrollment_token": "dtpd_…",
  "host_facts": {
    "hostname": "web-01.internal",
    "machine_id": "…",
    "os": "linux",
    "os_version": "Debian 13",
    "arch": "amd64",
    "agent_version": "0.1.0"
  }
}
```

`enrollment_token` is optional. `host_facts` is self-reported and authorizes
nothing — it is how a human recognises the machine in an approval queue.

**200** for every well-formed request:

```json
{
  "agent_id": "<uuid>",
  "registration_id": "<uuid>",
  "status": "pending",
  "key_fingerprint": "<64 hex characters>"
}
```

`status` is `pending` or `approved`, and **nothing about why**. A token that is
wrong, expired or exhausted produces the same `pending` an absent one does, so
this endpoint cannot be used to test whether a token is real.

**Idempotent on the public key.** Re-registering the same keypair resolves to
the same agent rather than creating a second identity for one machine.

**422** `{"error": "invalid_request", …}` for a missing `account_id` or
`public_key_pem`, or a `public_key_pem` that is not a readable public key.

---

## `POST /discovery/v1/token`

Exchange a signed assertion for a short-lived bearer.

```
X-DTP-Agent-Fingerprint: <64 hex characters>
```

```json
{
  "key_fingerprint": "<64 hex characters>",
  "issued_at": "2026-09-15T21:00:00Z",
  "nonce": "<16 to 128 characters>",
  "signature": "<base64 detached signature>"
}
```

### Building the assertion

A **detached signature**, not a JWT. DTP already holds your public key, so the
algorithm is a property of the key DTP stored and is never read from the
request: there is no `alg` field to confuse and no `none` to fall into.

Sign the SHA-256 digest of exactly these five lines joined with `\n`, in this
order, with no trailing newline:

```
DTP-DISCOVERY-AGENT-ASSERTION-v1
<key_fingerprint>
<issued_at>
<nonce>
dtp-discovery
```

Then base64 the signature. The **fingerprint is inside the signed string**,
which is what stops one agent's fingerprint being paired with another agent's
signature.

`key_fingerprint` is the lowercase hex SHA-256 of the **DER of your public key**
(SPKI), computed from the key rather than from the PEM text — so whitespace or
a re-encode cannot produce a second identity for one keypair.

### Freshness and replay

| | |
|---|---|
| `issued_at` | RFC 3339 / ISO 8601, UTC |
| accepted window | up to **2 minutes** in the future, **5 minutes** in the past |
| `nonce` | 16–128 characters, **single use**, enforced by a unique index |

A replayed nonce is refused. Never cache an assertion: it authenticates exactly
once, and a cached one fails afterwards in a way that looks like a server fault.

Clock drift on the host is the commonest cause of a fleet that suddenly cannot
authenticate. `checkin` returns the server's clock so a client can notice and
say so in its own logs.

### Responses

**200** — a bearer, valid for **15 minutes**:

```json
{ "access_token": "…", "token_type": "Bearer", "expires_in": 900 }
```

**202** — proved the key, not yet admitted. **This is a 2xx**; a client that
branches only on `err != nil` will treat it as success and proceed with an empty
token:

```json
{ "status": "pending_approval", "retry_after": 30, "message": "…" }
```

`Retry-After: 30` is also set. Running an installer before anyone has clicked
approve is the normal case in a rollout, so wait and retry rather than failing.

**403** — a valid key, refused standing: suspended, revoked, or the account
archived. Terminal; stop retrying.

```json
{ "status": "refused", "agent_status": "revoked" }
```

**401** `{"error": "invalid_assertion"}` with `WWW-Authenticate: Bearer` — for
**every** verification failure: unknown fingerprint, bad signature, stale clock,
replayed nonce. They are deliberately indistinguishable, so an unauthenticated
caller cannot enumerate which agents exist.

### The header is not optional in practice

Nothing in the application reads `X-DTP-Agent-Fingerprint`. The **rate limiter**
does, because middleware cannot parse a JSON body. An agent that omits it still
authenticates — and falls into the shared per-IP bucket with every other agent
behind the same address, which for a fleet inside one network is all of them.

It carries no authority: it is unverified, and the signed `key_fingerprint` in
the body is the only one trusted.

---

## `POST /discovery/v1/checkin`

```
Authorization: Bearer <access token>
```

```json
{ "agent_version": "0.1.0" }
```

**200**:

```json
{ "ok": true, "agent_id": "<uuid>", "server_time": "2026-09-15T21:00:00Z", "commands": [] }
```

`commands` is present and empty from the start, so a client can ship its polling
loop once. An agent may correct its **own** version here; everything else it
claimed stays frozen in the registration a reviewer saw.

---

## `POST /discovery/v1/inventory`

```
Authorization: Bearer <access token>
```

```json
{
  "run_id": "<your own id for this scan>",
  "started_at": "2026-09-15T21:00:00Z",
  "finished_at": "2026-09-15T21:04:00Z",
  "final": true,
  "completed_sources": ["file", "listener"],
  "collector_errors": [
    { "collector": "java_keystore", "error": "permission denied", "location": "/opt/app/ks.jks" }
  ],
  "observations": [
    {
      "certificate_pem": "-----BEGIN CERTIFICATE-----\n…",
      "chain_pem": "-----BEGIN CERTIFICATE-----\n…",
      "source": "file",
      "location": "/etc/nginx/tls/site.pem",
      "binding": { "server_name": "www.example.com" },
      "private_key_present": true,
      "private_key_location": "/etc/nginx/tls/site.key",
      "file_mode": "0600",
      "file_owner": "root",
      "observed_at": "2026-09-15T21:03:59Z"
    }
  ]
}
```

**At most 500 observations per request.** Page a larger estate under one
`run_id`: the server folds the pages into a single run, so a retried page is
free rather than opening a second run or double-counting. Only the last page
sets `final`.

`source` is one of `file`, `os_store`, `java_keystore`, `nss`, `listener`,
`server_config`. Anything else is filed as `other` rather than guessed at.

**200**:

```json
{ "run_id": "…", "status": "completed", "recorded": 42, "rejected": 1, "errors": ["…"] }
```

Rejections are **named, not merely counted**, so a client having half its
findings refused can see why in its own logs without anyone reading the
server's.

### `completed_sources` decides what is marked gone

It names the collectors that **finished cleanly**, and it is the only thing that
lets DTP conclude a certificate is no longer deployed somewhere.

Declare a source only if its sweep completed. A collector that hit a permission
error saw certificates it **could not see** — not certificates that were
removed — and reporting those as gone would send an operator looking for a
change that never happened.

The field is shaped so that the failure mode of omitting it is *nothing is ever
marked absent*: stale, visible, harmless. Not *certificates wrongly vanish*.

### Errors

| | |
|---|---|
| **413** `too_many_observations` | more than 500 in one page; `max` is in the body |
| **422** `invalid_request` | `run_id` missing |
| **422** `private_key_material` | the page contained a private key — refused loudly, **nothing stored** |
| **403** `not_reporting` | authenticated, but not bound to an account (approval revoked between minting the token and using it). The credential is fine; the standing is not |

---

## Private key material is never sent

The agent records **that** a key sits beside a certificate and **where** — an
operator needs to know a key exists and is mode `0644` — and never its bytes.

In this implementation that is enforced three times, and a client you write
should do something equivalent:

1. the observation type has **no field** for key bytes, so a new collector
   cannot leak them by filling something that was lying around;
2. certificates are **re-encoded from parsed DER** rather than sliced out of the
   file, so a key sharing the file (the haproxy layout) cannot ride along;
3. every outbound body is scanned and **refused locally**.

The server refuses such a payload too, with a 422 — but by then it has crossed
the network and been logged on the way. A guard that fires locally is a bug; one
that fires at the server is an incident.

---

## Rate limits

Per minute, as configured on the reference deployment:

| Endpoint | Per agent | Per IP |
|---|---|---|
| `register` | — | 10 |
| `token` | 20 | 120 |
| `checkin` | — | 120 |
| `inventory` | 60 | 300 |

The per-agent `token` limit keys on `X-DTP-Agent-Fingerprint`; the per-agent
`inventory` limit keys on the bearer. Omitting the header collapses your whole
fleet into the per-IP bucket.

---

## Versioning

The path carries the version because the agent is software on machines DTP does
not control: an old binary keeps working against `/discovery/v1` long after the
platform has moved on. That is not a nicety — it is the only way a fleet is ever
upgradable.

New **optional** fields may appear in requests and responses within `v1`. Ignore
what you do not recognise. Anything that changes the meaning of an existing
field gets a new version.
