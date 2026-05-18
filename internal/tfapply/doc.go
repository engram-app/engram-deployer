// Package tfapply orchestrates terraform-apply runs against the local
// Docker socket on FastRaid, driven by /tf-apply HTTP requests.
//
// Flow per request:
//
//  1. Wipe + recreate a working directory.
//  2. Shallow-clone github.com/engram-app/engram-infra at the requested
//     git SHA.
//  3. cd into the configured root (e.g. main/envs/staging-fastraid).
//  4. terraform init (S3 backend, AWS creds inherited from env).
//  5. terraform apply -auto-approve -input=false.
//
// Stdout/stderr from git + terraform is streamed line-by-line back to
// the HTTP caller as TFApplyEvent records, so the GitHub Actions
// workflow that POSTed the request gets live progress in its job log.
//
// The terraform apply targets the Docker provider against the local
// /var/run/docker.sock — no outbound AWS API calls happen during apply
// (only state RW). State lives at
//
//	s3://engram-infra-tfstate-751667630925/main/staging-fastraid.tfstate
//
// and the daemon's IAM user (engram-deployer-tf) is scoped strictly to
// that one object prefix.
package tfapply
