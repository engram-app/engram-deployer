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

Three independent gates on every `/deploy`, `/tf-apply`, and `/tf-plan`:

1. **OIDC** — JWT signature verified against GitHub's JWKS. Each endpoint
   pins its OWN audience + repository + workflow allowlist:
   - `/deploy` accepts only `aud=engram-deploy`, `repository=engram-app/Engram`,
     `workflow_ref=engram-app/Engram/.github/workflows/ci.yml@refs/heads/main`.
   - `/tf-apply` accepts only `aud=engram-tf-apply`,
     `repository=engram-app/engram-infra`,
     `workflow_ref=engram-app/engram-infra/.github/workflows/tf-apply.yml@refs/heads/main`.
   - `/tf-plan` accepts only `aud=engram-tf-plan`,
     `repository=engram-app/engram-infra`,
     `sub=repo:engram-app/engram-infra:pull_request`, and a `workflow_ref`
     prefixed by `engram-app/engram-infra/.github/workflows/tf-plan.yml@`.
     `ref` is not pinned because PR-event tokens carry `refs/pull/N/merge`
     which varies per PR.
   - A token minted for one endpoint cannot drive any of the others.
2. **JTI replay** — each token's `jti` is recorded across ALL three endpoints;
   second sighting refused regardless of which endpoint saw it first.
3. **Source IP allowlist** — only the runner VM's IP at the daemon layer
   (firewall also enforces this at the host).

Plus: TLS on the wire (self-signed cert, pinned in CI), firewall rule on
SlowRaid permitting only VM → FastRaid:8443. `/deploy`, `/tf-apply`, and
`/tf-plan` serialize on a single internal mutex — apply mutates Docker
state, plan shares the terraform workdir + state lock, so concurrent
runs would clash.

## Endpoints

| Method | Path                | Auth | Purpose |
|--------|---------------------|------|---------|
| POST   | `/deploy`           | OIDC | Pull + restart engram-saas/selfhost at a given version |
| POST   | `/tf-apply`         | OIDC | Run `terraform apply` against local Docker socket (engram-infra @sha) |
| POST   | `/tf-plan`          | OIDC | Run `terraform plan` at a PR @sha and stream the diff (no apply) |
| GET    | `/status`           | none | Last `/deploy` result |
| GET    | `/tf-apply/status`  | none | Last `/tf-apply` result |
| GET    | `/tf-plan/status`   | none | Last `/tf-plan` result |
| GET    | `/healthz`          | none | Liveness probe |

`/tf-apply` and `/tf-plan` are opt-in — both wired when any
`DEPLOYER_TF_APPLY_*` env is configured. They share repo, root, AWS
creds, and orchestrator; only the OIDC validator differs.

## Repo layout

```
cmd/deployer/         Entrypoint
internal/auth/        OIDC + JTI + IP allowlist
internal/server/      TLS HTTP server, /deploy /tf-apply /tf-plan /status /healthz
internal/deploy/      Pure-Go deploy logic (docker pull/tag, template edit,
                      update_container exec, health poll)
internal/tfapply/     terraform-apply + terraform-plan orchestrator (git clone +
                      tf init + apply | plan) — single Orchestrator implements
                      both server.TFApplier and server.TFPlanner
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
