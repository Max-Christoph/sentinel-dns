# sentinel-dns

A small DNS sinkhole for edge hardware. It answers DNS queries immediately and
classifies telemetry domains asynchronously with a pluggable AI backend
(Ollama, any OpenAI-compatible endpoint) or a deterministic heuristic.

The synchronous path never waits for a model: cache miss → forward upstream →
answer → enqueue. Classification happens in a bounded worker pool, and its
verdict is written to SQLite and the in-memory cache so the next lookup is
answered locally with `0.0.0.0` / `::`.

```
client ──A/AAAA──▶ sentineld (:53 udp+tcp)
                      │
        ┌─────────────┴─────────────┐
        │ cache hit, blocked        │ hit allowed / miss
        ▼                           ▼
  0.0.0.0 / ::               upstream resolver ──▶ client
                                    │
                            miss → non-blocking enqueue
                                    ▼
                        ┌───────────────────────┐
                        │ worker pool (2-4)     │
                        │ dedup per domain      │
                        └──────────┬────────────┘
                                   ▼
                     heuristic │ Ollama │ OpenAI-compatible
                                   │
                          SQLite (WAL) + cache update
```

## Properties

- **Static binary, no CGO.** `modernc.org/sqlite` instead of `mattn/go-sqlite3`,
  so `CGO_ENABLED=0` cross-compilation to arm/arm64 is a single command.
- **No blocking on the DNS path.** The query channel has a fixed buffer and a
  `select`/`default` send; a full queue drops the classification, never the
  answer.
- **In-flight deduplication.** A domain that is already being classified is not
  queued again (`sync.Map` key set at submit, cleared when the worker finishes).
- **Fail-safe.** Provider errors never produce a block decision. They suppress
  retries for 90 s and are logged rate-limited.
- **Restart-safe.** Verdicts are read back from SQLite at startup, so a restart
  does not re-classify known domains.
- **Bounded memory.** Cache is capped (`cache.max_entries`); expired entries are
  reclaimed on insert.

## Non-goals

- Not a recursive resolver, not DNSSEC-validating, no DoH/DoT listener.
- No wildcard blocking: `metrics.vendor.example` and `cdn.vendor.example` are
  decided independently.
- Blocking applies to `A` and `AAAA` only. `TXT`, `MX`, `HTTPS`, ... are always
  forwarded.
- Single node, no clustering, no query-log UI. The SQLite file is the UI.

## Requirements

- Go 1.23 or newer (module pins `go 1.23.0`; `miekg/dns` and `modernc.org/sqlite`
  are held at versions that still build with it).
- Port 53 on the host, or a NAT redirect in front of it.

## Build

```bash
git clone https://github.com/Max-Christoph/sentinel-dns.git
cd sentinel-dns
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=$(git describe --tags --always)" \
  -o sentineld ./cmd/sentineld
sudo install -m 0755 sentineld /usr/local/bin/sentineld
```

Cross-compilation:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="-s -w" -o sentineld-arm64 ./cmd/sentineld
CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOFLAGS=-buildmode=pie go build ...   # armv7, if needed
```

Verify the static link: `ldd sentineld` must print `not a dynamic executable`.

## Configure

```bash
sudo mkdir -p /etc/sentinel-dns /var/lib/sentinel-dns
sudo cp config.example.yaml /etc/sentinel-dns/config.yaml
sudo $EDITOR /etc/sentinel-dns/config.yaml
```

Provider secrets belong in an environment file (`/etc/sentinel-dns/env`, mode
`0640`), not in the YAML: `api_key_env: "OLLAMA_API_KEY"` is read from the
process environment, and the systemd unit loads that file via `EnvironmentFile=`.

Every key is optional; omitted keys keep the default below.

| Key | Default | Meaning |
| --- | --- | --- |
| `listen.udp` | `0.0.0.0:53` | UDP listener |
| `listen.tcp` | `0.0.0.0:53` | TCP listener, `""` disables it |
| `upstream.addresses` | `9.9.9.9:53`, `149.112.112.112:53` | tried in order |
| `upstream.timeout` | `2s` | per resolver, per attempt |
| `cache.blocked_ttl` | `300s` | how long a block verdict stays hot |
| `cache.allowed_ttl` | `600s` | how long an allow verdict suppresses re-classification |
| `cache.max_entries` | `50000` | `0` = unbounded |
| `database.path` | `/var/lib/sentinel-dns/sentinel.db` | SQLite file, parent directory is created |
| `workers.pool_size` | `3` | 2–4 is the useful range on a Pi |
| `workers.queue_size` | `1024` | buffered jobs before drops start |
| `workers.job_timeout` | `25s` | hard cap per classification |
| `blocking.ipv4` / `blocking.ipv6` | `0.0.0.0` / `::` | sinkhole answers |
| `blocking.ttl` | `300` | TTL of the sinkhole answer |
| `blocking.min_confidence` | `0.6` | verdicts below this never block |
| `logging.level` / `logging.format` | `info` / `text` | `debug`,`info`,`warn`,`error`; `text`,`json` |
| `provider.type` | `heuristic` | `heuristic`, `ollama`, `openai`, `systemone` |
| `blocking.category_min_probability` | `0.7` | a confident category label may block even when the yes/no question hesitates |
| `blocking.allowlist` | vendor infrastructure (Google, Microsoft NCSI, captive portals, OCSP) | exact name or subdomain, never sinkholed |
| `provider.systemone.enrich_category` | `true` | second, category-only call for blocked domains (systemone, `questions: tracking`) |
| `provider.timeout` | `20s` | HTTP client timeout |

Run in the foreground while testing:

```bash
sudo /usr/local/bin/sentineld -config /etc/sentinel-dns/config.yaml
```

Flags: `-config <path>`, `-version`, `-prune-days <n>` (delete decisions not
updated for n days at startup, `0` disables).

## Decision providers

All providers return `{"block":bool,"confidence":0..1,"reason":string}` and may
add `"category"` (`telemetry`, `analytics`, `ads`, `crash`, ...). A verdict
blocks only when `block == true` **and** `confidence >= blocking.min_confidence`.

### heuristic (default, no network)

Label-exact keyword rules (`metrics`, `telemetry`, `analytics`, `tracking`,
`collector`, `beacon`, `pixel`, `acr`, `crashlytics`, `app-measurement`, ...),
prefix rules (`log-`, `telemetry-`, `metrics-`, `stats-`) and a handful of
vendor suffixes (`doubleclick.net`, `google-analytics.com`, `segment.io`, ...).
Substring matching is deliberately not used, so `acrobat.com` and
`logs.example.com` do not match `acr` / `log-`.

Add domains with `provider.heuristic.extra_patterns` (matched as suffix):

```yaml
provider:
  type: heuristic
  heuristic:
    extra_patterns: ["tracking.vendor.example"]
```

This backend is a baseline, not a classifier: expect false negatives on novel
telemetry and occasional false positives on names that embed a keyword.

### systemone (Clef decision models, hosted or local)

Clef is a **decision model**, not a chat model: it answers typed questions in a
single forward pass and returns probabilities. It is served on
`/v1/systemone`, not `/v1/chat/completions`, so it uses its own provider.

```yaml
provider:
  type: systemone
  timeout: 20s
  systemone:
    # API root or the full endpoint, both work:
    #   https://ollama.com/v1  or  https://ollama.com/v1/systemone
    #   http://127.0.0.1:11434/v1 for a local Ollama >= 0.35
    base_url: "https://ollama.com/v1/systemone"
    model: "clef:27b"                  # alias "clef:27b-cloud" also works
    api_key_env: "OLLAMA_API_KEY"
    questions: "tracking"             # or "tracking_category"
```

The default sends **one** `noul` question per domain:

> Does this domain primarily serve tracking, user analytics, ads, crash metrics,
> or behavioural profiling, including vendor-specific CDNs serving tracking
> scripts? Answer false for first-party application APIs, multi-tenant content
> delivery (media/static assets), authentication, and essential OS
> infrastructure. Judge only the DNS name; no page content is available.

Mapping into the decision pipeline:

- `block` = `p >= 0.5`, then the policy (`provider.Policy`) applies
  `blocking.min_confidence` (0.6) exactly once
- `confidence` = `max(p, 1-p)` — the certainty of the verdict
- `reason` = raw probabilities, never a generated sentence
- `state` is the domain name only. The client IP is deliberately **not** sent: it
  carries no signal about the domain and measurably perturbs the joint score
  (`connect.facebook.net` 0.631 with domain-only state vs 0.398 with a client-IP
  line in the same prompt)

**`questions: "tracking_category"`** adds a second, `choice`-type question
(`telemetry` / `analytics` / `ads` / `benign`). It fills `device_category`, but
Clef scores all questions in one joint pass, so the extra question shifts the
tracking probability by up to ±0.44 on borderline names and adds latency. Measured
on the same 24-domain tracker set: `tracking` blocks 20, `tracking_category`
blocks 19 — with a different set of misses.

**Post-block enrichment (`enrich_category: true`, default).** After a domain is
blocked, a second, category-only request runs on its own single-worker pool and
backfills `device_category` — the decision request stays on the well-separated
prompt. The DNS answer and the cache entry are already in place when it starts,
so nothing waits for it.

- The label is only written when `p(category) >= blocking.min_confidence`;
  otherwise the column stays empty. An empty cell is honest, a guessed category
  in a dashboard is not.
- It never touches `blocked`, `confidence`, `reasoning` or `hit_count`; the
  original decision stays the audit trail.
- Measured on the 24-domain tracker set: 20 blocked, 20 enrichment calls, 12 of
  them produced a label above 0.6 (`analytics` 7, `ads` 4, `telemetry` 2,
  `benign` 1). Labels arrive 0.6 s after the decision when the queue is empty;
  under 20 simultaneous hits the single worker needed up to ~11 s, which is
  irrelevant because nothing blocks on it.
- `questions: "tracking_category"` makes the enrichment redundant; use one or
  the other.

**Calibration matters more than wording.** Identical requests are deterministic
(5/5 identical scores), but every change to the payload — wording, sibling
questions, even a metadata line — changes the numbers. Treat scores in the
0.2–0.6 band as noise, not as a property of the domain.

Measured against `https://ollama.com/v1` (2026-10-29, German uplink):

| Sample | Result |
| --- | --- |
| 24 known tracker domains | 20 blocked, threshold 0.6 |
| 17 benign controls (jsDelivr, cdnjs, Google Fonts, Netflix, Akamai, PayPal, GitHub, Microsoft 365, Docker, S3, Wikimedia) | 0 blocked; highest score 0.41 (`ajax.googleapis.com`) |
| Latency | 555 ms median, 623 ms max; 161–330 input tokens |

Known misses with the default prompt: `sc-static.net` (0.14), `secure.quantserve.com`
(0.14), `snap.licdn.com` (0.20), `s.pinimg.com` (0.20). All sit far below the
threshold, so they are stable misses rather than noise — add them to
`provider.heuristic.extra_patterns` if you need them covered.

### ollama

### ollama

```yaml
provider:
  type: ollama
  timeout: 20s
  ollama:
    endpoint: "http://127.0.0.1:11434"
    model: "d1"
```

Uses `POST /api/generate` with `"format": "json"`, `stream: false` and a
few-shot prompt. Any JSON-capable model works; small decision models
(`d1`, `d3`) answer in well under a second on a Pi 4 if the model stays
resident. Keep `workers.job_timeout` above the model's worst-case latency.

### openai (OpenAI, Cloudflare Workers AI, vLLM, llama.cpp)

```yaml
provider:
  type: openai
  timeout: 20s
  openai:
    base_url: "https://api.openai.com/v1"
    model: "gpt-4o-mini"
    api_key_env: "OPENAI_API_KEY"
    json_mode: true
    headers: {}
```

`POST {base_url}/chat/completions` with `response_format: {"type":"json_object"}`
(disable via `json_mode: false` for backends that reject it). `api_key` is read
from the config or, preferably, from `api_key_env`.

Cloudflare Workers AI example:

```yaml
provider:
  type: openai
  openai:
    base_url: "https://api.cloudflare.com/client/v4/accounts/<account-id>/ai/v1"
    model: "@cf/meta/llama-3.1-8b-instruct"
    api_key_env: "CLOUDFLARE_API_TOKEN"
    json_mode: false
```

## Deploy with systemd

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin sentinel-dns
sudo install -d -m 0750 -o root -g sentinel-dns /etc/sentinel-dns
printf 'OLLAMA_API_KEY=%s\n' '<key>' | sudo tee /etc/sentinel-dns/env >/dev/null
sudo chmod 0640 /etc/sentinel-dns/env
sudo install -m 0644 deploy/sentinel-dns.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now sentinel-dns
journalctl -u sentinel-dns -f
```

The unit grants only `CAP_NET_BIND_SERVICE`, mounts the filesystem read-only
and writes to `/var/lib/sentinel-dns` via `StateDirectory`.

## Deploy with Docker

```bash
cp config.example.yaml config.yaml     # edit provider + upstream
mkdir -p data && sudo chown 65532:65532 data
docker compose up -d --build
docker compose logs -f
```

The image is `scratch` + static binary (~13 MB). The container runs as UID
65532 and binds port 53 through `net.ipv4.ip_unprivileged_port_start=0`; the
compose file sets that sysctl, drops all capabilities and mounts the root
filesystem read-only.

Point the DHCP DNS option at the Docker host's IP. Nothing else is exposed.

## Deploy on MikroTik RouterOS 7

RouterOS can run the image as a container, but it cannot build it — you need a
registry or an uploaded tarball. Container mode requires physical access to the
device (reset button / cold reboot) and the `container` extra package.

```bash
# 1. enable container mode (follow the prompt, then reboot)
/system/device-mode/update container=yes

# 2. network: bridge + veth + masquerade for the container's own upstream traffic
/interface/bridge/add name=containers
/ip/address/add address=172.17.0.1/24 interface=containers
/interface/veth/add name=veth-sentinel address=172.17.0.2/24 gateway=172.17.0.1
/interface/bridge/port/add bridge=containers interface=veth-sentinel
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.17.0.0/24

# 3. persistent storage (works on 7.15+; older builds may call it /file/mkdir)
/file/add name=disk1/sentinel/etc type=directory
/file/add name=disk1/sentinel/data type=directory
/container/mounts/add list=SENTINEL_ETC  src=disk1/sentinel/etc  dst=/etc/sentinel-dns
/container/mounts/add list=SENTINEL_DATA src=disk1/sentinel/data dst=/var/lib/sentinel-dns

# 4. put your config.yaml into disk1/sentinel/etc/ (WinBox drag & drop or scp)

# 5. image: either pull from a registry ...
/container/config/set registry-url=https://registry-1.docker.io tmpdir=disk1/tmp
/container/add remote-image=<owner>/sentinel-dns:0.1.0 interface=veth-sentinel \
    root-dir=disk1/sentinel/root mountlists=SENTINEL_ETC,SENTINEL_DATA \
    user=0:0 logging=yes start-on-boot=yes name=sentinel-dns
#    ... or import a tarball: docker save sentinel-dns:0.1.0 | gzip > sentinel-dns.tar.gz,
#    upload it to disk1, then: /container/add file=disk1/sentinel-dns.tar.gz ...
#    (RouterOS < 7.20 needs Docker-format tars, 7.20+ accepts OCI tar.gz)

/container/start [find name=sentinel-dns]
/container/print              # status must become "running"
/log print where topics~"container"
```

The image runs as UID 65532, which cannot bind port 53 in the RouterOS
container netns — hence `user=0:0`. That is a real privilege escalation inside
the container; only do it for images you trust and pin by digest.

Redirect LAN DNS to the container:

```bash
/ip/firewall/nat/add chain=dstnat in-interface-list=LAN protocol=udp dst-port=53 \
    action=dst-nat to-addresses=172.17.0.2 to-ports=53
/ip/firewall/nat/add chain=dstnat in-interface-list=LAN protocol=tcp dst-port=53 \
    action=dst-nat to-addresses=172.17.0.2 to-ports=53
# if your forward chain drops by default:
/ip/firewall/filter/add chain=forward dst-address=172.17.0.2 protocol=udp dst-port=53 action=accept place-before=0
/ip/firewall/filter/add chain=forward dst-address=172.17.0.2 protocol=tcp dst-port=53 action=accept place-before=0
```

Because destination NAT is applied in `prerouting`, these rules also catch
clients that still use the router itself (`192.168.88.1`) as resolver — the
RouterOS DNS service never sees the packet. Keep DHCP handing out the router IP
so guests are covered.

Verify from a LAN host:

```bash
dig @192.168.88.1 metrics.vendor.example A +short    # 0.0.0.0 after classification
dig @192.168.88.1 example.com A +short               # normal upstream answer
```

Caveats:

- Container support is arm, arm64 and x86 only; build the matching image
  (`docker buildx build --platform linux/arm64 ...`).
- Use external storage (`disk1/...`), not the internal flash.
- The container needs working outbound NAT/DNS to reach its upstream resolvers.

## Database

SQLite in WAL mode, one table:

| Column | Type | Notes |
| --- | --- | --- |
| `domain` | TEXT PK | lower-case, no trailing dot |
| `device_category` | TEXT | from the provider verdict, may be empty |
| `is_telemetry` | INTEGER | the provider's raw `block` flag |
| `blocked` | INTEGER | the effective decision after `min_confidence` |
| `confidence` | REAL | clamped to 0..1 |
| `reasoning` | TEXT | model justification |
| `client_ip` | TEXT | last client that triggered a classification |
| `hit_count` | INTEGER | number of classifications, not DNS queries |
| `created_at`, `updated_at` | TEXT | RFC 3339, UTC |

`hit_count` deliberately counts classifications: incrementing it per query
would put a write on the hot path.

```bash
sqlite3 /var/lib/sentinel-dns/sentinel.db \
  "SELECT domain, device_category, confidence, hit_count FROM decisions WHERE blocked=1 ORDER BY updated_at DESC LIMIT 20;"
```

Housekeeping: run `sentineld -config ... -prune-days 90` from a weekly timer, or
delete rows manually. Without pruning the table grows with every unique domain
that was ever looked up.

### Allowlist

Some domains must never be sinkholed, whatever the model says: Google's
`signaler-pa.clients6.google.com` scored 0.604 once and broke Google apps, and a
blocked NCSI probe makes Windows claim "no internet" while browsing still works.
`blocking.allowlist` is checked in the DNS handler **before** the cache, so an
allowlisted name is always forwarded and never classified — existing blocked
rows for those names are ignored, not repaired.

Entries match exactly and as subdomains (`google.com` covers
`gemini.google.com`, but not `google-analytics.com`). The default list covers
Google core, Microsoft NCSI and update endpoints, captive-portal probes and two
OCSP responders. Add to it rather than lowering `min_confidence`.

## Security notes

- This is an unauthenticated DNS service. Never expose port 53 to the WAN;
  scope the NAT rule to the LAN interface list and drop 53/tcp+udp from WAN.
- With an HTTP provider, the domain and the client IP leave your network on
  every cache miss. Use a local Ollama endpoint if that is unacceptable.
- The heuristic is not a security control. Sinkholing is advisory: clients with
  hardcoded IPs, DoH, or their own resolver bypass it entirely.
- The provider response is untrusted input: JSON is parsed defensively, the
  confidence is clamped, and a missing `block` field is an error, never a
  default.
- RouterOS containers run as root on the router. Pin image digests and rebuild
  from source if you did not build the image yourself.

## Development

```bash
go test ./...          # unit + end-to-end tests (UDP/TCP upstream stubs, no network egress)
go test -race ./...
go vet ./...
```

Layout:

```
cmd/sentineld        wiring, flags, graceful shutdown, stats logging
internal/config      YAML parsing, defaults, validation (all problems at once)
internal/dns         cache, handler, blocked answers, upstream with TCP fallback
internal/queue       bounded worker pool, in-flight dedup, counters
internal/store       SQLite (WAL) schema, upsert, preload, prune
internal/provider    interface + ollama + openai-compatible + heuristic
```

The handler is testable without sockets: `dnsserver.Options` takes a
`Forwarder` and a `SubmitFunc`, so `server_test.go` covers routing with fakes
while `e2e_test.go` drives a real UDP listener.

## License

MIT — see [LICENSE](LICENSE).
