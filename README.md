# cgep-app-starter

> Patient Intake API for "Acme Health". The deliberately-flawed workload your **CGE-P capstone** wraps with GRC controls.

## What this is

A minimal AWS workload: VPC, Lambda, API Gateway, DynamoDB, S3. It ingests patient intake submissions over HTTPS. Think of it as a system you have just inherited from an engineering team and been asked to make audit-defensible.

This repository ships **non-compliant on purpose**. Your job in the capstone is not to rewrite this app. Your job is to wrap it with the four CGE-P layers (Terraform GRC baseline, Rego policies, GitHub Actions evidence pipeline, OSCAL component) so the same workload becomes audit-defensible against HIPAA, SOC 2, and CMMC L2.

## The deploy gate

If you cannot deploy this starter, you cannot pass the capstone. Real GRC engineers inherit working systems. Step zero is making the system run.

```bash
git clone https://github.com/GRCEngClub/cgep-app-starter
cd cgep-app-starter

# Confirm you're authenticated to the right account:
make creds AWS_PROFILE=<your-sandbox-profile>

make deploy AWS_PROFILE=<your-sandbox-profile>
make test    AWS_PROFILE=<your-sandbox-profile>
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's AWS provider can fail to read it directly with `failed to find SSO session section`. The Makefile's `eval $(aws configure export-credentials)` pattern handles this. If you're running `terraform` commands by hand, do the same export first.

Expected output of `make test`:

```json
{
    "submission_id": "f1e3...",
    "status": "received"
}
```

When you're done exploring: `make destroy`.

## What you build on top

Fork the repo into your own `cgep-capstone` and add:

1. **Layer 1 — GRC baseline (Terraform).** KMS keys, an S3 evidence vault with Object Lock, a CloudTrail trail. Bring this starter's data stores under your CMK.
2. **Layer 2 — OPA policy suite (Rego).** Five or more policies that catch the named gaps in [GAPS.md](GAPS.md). Each policy maps to at least one control from the framework you choose.
3. **Layer 3 — GitHub Actions pipeline.** Plan → Conftest gate → apply → Cosign sign → upload to vault.
4. **Layer 4 — OSCAL component.** A `component-definition.json` describing how your governed system implements its controls.

Full brief: `docs/labs/07_01_capstone_brief.md` in the course content repo.

## Framework mapping is required

Your capstone must declare a primary framework: **HIPAA Security Rule**, **SOC 2 Trust Services Criteria**, or **CMMC Level 2**. Every policy carries at least one control ID from your chosen framework. Your OSCAL component's `control-implementations` reference your framework's catalog.

A starter mapping is in [FRAMEWORKS.md](FRAMEWORKS.md). It is not the only valid mapping. You're expected to defend yours.

## Cost

Roughly $0 if destroyed within an hour. Lambda + API Gateway + DynamoDB + S3 are all pay-per-use, and an empty deployment generates no traffic. CloudTrail (which you add) costs cents.

## Layout

```
cgep-app-starter/
├── README.md            # this file
├── WORKLOAD.md          # what the API does
├── GAPS.md              # the named flaws your policies must catch
├── FRAMEWORKS.md        # HIPAA / SOC 2 / CMMC mapping primer
├── Makefile             # make deploy | test | destroy
├── terraform/
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   └── lambda/handler.py
└── test/
    └── intake.sh
```

## License

MIT. Fork freely. Submissions remain learners' own work.

## Capstone verification (for the grader)

This repo is a fork of `GRCEngClub/cgep-app-starter`, wrapped with a CMMC
Level 2 GRC baseline. Primary framework and full design reasoning: see
`WRITEUP.md`.

1. **Terraform baseline** — `terraform/kms.tf`, `terraform/evidence_vault.tf`,
   `terraform/cloudtrail.tf`, `terraform/vpc_endpoints.tf`,
   `terraform/s3_uploads_hardening.tf`,
   `terraform/dynamodb_hardening_override.tf`, `terraform/main_override.tf`,
   `terraform/lambda_security_group.tf`, `terraform/github_oidc.tf`,
   `terraform/backend.tf`, `terraform/backend_bootstrap.tf` — all
   additions, the starter's own `main.tf` / `variables.tf` / `outputs.tf`
   are untouched.
2. **Policy suite** — `opa test policies/` (6 policies, 15 tests, all
   passing).
3. **Pipeline** — `.github/workflows/grc-gate.yml`. See PR #1 (merged,
   triggered the full pipeline including the post-merge apply, sign, and
   evidence upload) and PR #2 (`[DEMO — do not merge] Reintroduce GAP-01
   to prove the gate fires`, blocked by the Conftest policy gate citing
   SC.L2-3.13.11, closed unmerged) for the gate working both directions.
4. **Signed evidence** — `s3://acme-health-intake-evidence-vault-da40cebe/runs/31912403798/`.
   Verify:
   ```
   cosign verify-blob --bundle evidence-31912403798-5a509fc7f48866359884638a5466c3e1137c52e7.tar.gz.sig.bundle \
     --certificate-identity-regexp "https://github.com/Shayl-Taveras/cgep-app-starter/.github/workflows/grc-gate.yml@.*" \
     --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
     evidence-31912403798-5a509fc7f48866359884638a5466c3e1137c52e7.tar.gz
   ```
5. **OSCAL** — `oscal/components/acme-health-intake.json`,
   `oscal/profiles/cmmc-l2-minimum.json`. Validate:
   ```
   trestle validate -f component-definitions/acme-health-intake/component-definition.json
   ```
   (see `oscal/evidence/trestle-validate.txt` for a captured run).
