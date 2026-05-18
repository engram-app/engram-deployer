# engram-deployer

Pull-based deploy daemon for [Engram](https://github.com/engram-app/Engram) on
FastRaid. Replaces the previous CI-pushes-via-SSH-as-root pattern.

## Why

Old flow: GitHub Actions runner held an SSH key for `root@FastRaid` and ran
`fastraid-deploy.sh` over SSH after building the image. Runner RCE meant root
on FastRaid. Nuclear blast radius.

New flow: runner only builds + pushes the image to GHCR, then posts a signed
deploy request to this daemon. Daemon runs on FastRaid itself (host service
installed via Unraid plugin) and executes the deploy locally. Runner holds
**zero** long-lived credentials.

## Architecture

```
┌────────────────┐  1. build + push image to GHCR
│ Isolated CI    │ ───────────────────────────────────────▶  ghcr.io
│ runner VM      │
│                │  2. mint GitHub OIDC JWT (per-job, ~15min lifetime)
│                │  3. POST https://10.0.20.214:8443/deploy
│                │     Authorization: Bearer <oidc-jwt>
│                │     Body: { "version": "0.5.61", "sha": "abc1234" }      ┌──────────────────┐
│                │ ◀─────────────────────────────────────────────────────── │ engram-deployer  │
│                │  4. chunked stream: pulling / starting / healthy / done  │ on FastRaid host │
│                │  5. exit code reflects deploy outcome (green = deployed) │ (Unraid plugin)  │
└────────────────┘                                                          └──────────────────┘
                                                                                     │
                                                                       validates JWT │
                                                                       against GitHub
                                                                       JWKS (cached)
```

## Security model

Three independent gates on every `/deploy` and every `/tf-apply`:

1. **OIDC** — JWT signature verified against GitHub's JWKS. Each endpoint
   pins its OWN audience + repository + workflow_ref allowlist:
   - `/deploy` accepts only `aud=engram-deploy`, `repository=engram-app/Engram`,
     `workflow_ref=engram-app/Engram/.github/workflows/ci.yml@refs/heads/main`.
   - `/tf-apply` accepts only `aud=engram-tf-apply`,
     `repository=engram-app/engram-infra`,
     `workflow_ref=engram-app/engram-infra/.github/workflows/tf-apply.yml@refs/heads/main`.
   - A token minted for one endpoint cannot drive the other.
2. **JTI replay** — each token's `jti` is recorded across BOTH endpoints;
   second sighting refused regardless of which endpoint saw it first.
3. **Source IP allowlist** — only the runner VM's IP at the daemon layer
   (firewall also enforces this at the host).

Plus: TLS on the wire (self-signed cert, pinned in CI), firewall rule on
SlowRaid permitting only VM → FastRaid:8443. `/deploy` and `/tf-apply`
serialize on an internal mutex so they cannot mutate Docker state
concurrently.

## Endpoints

| Method | Path                | Auth | Purpose |
|--------|---------------------|------|---------|
| POST   | `/deploy`           | OIDC | Pull + restart engram-saas/selfhost at a given version |
| POST   | `/tf-apply`         | OIDC | Run `terraform apply` against local Docker socket (engram-infra @sha) |
| GET    | `/status`           | none | Last `/deploy` result |
| GET    | `/tf-apply/status`  | none | Last `/tf-apply` result |
| GET    | `/healthz`          | none | Liveness probe |

`/tf-apply` is opt-in — wired only when `DEPLOYER_TF_APPLY_*` env is configured.

## Repo layout

```
cmd/deployer/         Entrypoint
internal/auth/        OIDC + JTI + IP allowlist
internal/server/      TLS HTTP server, /deploy /tf-apply /status /healthz
internal/deploy/      Pure-Go deploy logic (docker pull/tag, template edit,
                      update_container exec, health poll)
internal/tfapply/     terraform-apply orchestrator (git clone + tf init + apply)
package/              Unraid plugin (.plg) + rc.d start script
```

## Build + run

```bash
go build -o engram-deployer ./cmd/deployer
./engram-deployer
```

External binaries on the host (required when `/tf-apply` is enabled):
`terraform`, `git`. Pinned via `DEPLOYER_TF_BINARY_PATH` /
`DEPLOYER_TF_GIT_BINARY_PATH` env if not on PATH.
