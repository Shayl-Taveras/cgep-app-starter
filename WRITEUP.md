# Design Write-Up: Acme Health Patient Intake API GRC Baseline

Primary framework: **CMMC Level 2**. Chosen over HIPAA Security Rule and
SOC 2 TSC because it inherits NIST SP 800-171 Rev 3's control set, which
has a real, NIST-published, machine-readable OSCAL catalog
(`https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-171/rev3/json/NIST_SP800-171_rev3_catalog.json`).
HIPAA has no official OSCAL catalog (informal mapping to SP 800-66 Rev 2
at best) and SOC 2 has no official AICPA catalog either (practitioners map
TSC to NIST 800-53 as an indirection). Layer 4's grading criterion is
explicit that `control-implementation.source` must resolve to a real
catalog for the declared framework. CMMC L2 is the only one of the three
where that's a direct citation rather than a workaround.

## Gap remediation

`GAPS.md` names eight flaws in the starter. Six close in Terraform, each
with a matching Rego policy so CI catches regression, not just initial
state. Two are documented here as deferred rather than half-built.

| Gap | Resource | CMMC practice | Status |
|---|---|---|---|
| GAP-01: S3 uploads bucket used SSE-S3, not a customer CMK | `aws_s3_bucket.uploads` | SC.L2-3.13.11 | Closed |
| GAP-02: DynamoDB used the AWS-owned key, not a CMK | `aws_dynamodb_table.intake` | SC.L2-3.13.11 | Closed |
| GAP-03: no TLS-only bucket policy | `aws_s3_bucket.uploads` | SC.L2-3.13.8 | Closed |
| GAP-04: no S3 versioning | `aws_s3_bucket.uploads` | MP.L2-3.8.9 | Closed |
| GAP-05: Lambda ran outside the starter's VPC | `aws_lambda_function.intake` | SC.L2-3.13.1 | Closed |
| GAP-07: IAM role had `dynamodb:*`/`s3:*` | `aws_iam_role_policy.lambda_inline` | AC.L2-3.1.5 | Closed |
| GAP-06: no reserved concurrency, DLQ, or X-Ray | `aws_lambda_function.intake` | SI.L2-3.14.6 | Deferred |
| GAP-08: no API Gateway access logging, throttling, or WAF | `aws_apigatewayv2_stage.default` | AU.L2-3.3.1 | Deferred |

GAP-06 and GAP-08 were the two I cut deliberately. Both are operational
resilience and observability controls (keeping a Lambda from being
overwhelmed, keeping an API Gateway stage from being abused), not
confidentiality or access-boundary controls. The six I closed all sit on
the direct path PHI takes through this system: who can read it (GAP-07),
what protects it at rest (GAP-01, GAP-02), what protects it in transit
(GAP-03), whether an accidental overwrite is recoverable (GAP-04), and
whether the compute that touches it has a network path out to anywhere
else (GAP-05). In a two-day build, six gaps closed with real Terraform,
real Rego regression tests, and real signed evidence is a sharper CMMC L2
story than eight gaps half-covered. GAP-06 and GAP-08 would strengthen the
availability and audit-logging side of the same system, but they don't
change who can get to the PHI or what happens to it once someone does,
which is the story this baseline is telling.

## Design trade-offs

**Framework: CMMC Level 2.** Covered above: the deciding factor was
Layer 4's requirement that the OSCAL `control-implementation.source`
resolve to a real, NIST-published catalog. HIPAA and SOC 2 both would have
required an indirect mapping through a catalog that isn't their own.

**Region: us-east-1.** Matches the starter's own default, so no variable
overrides were needed to keep the workload and the added GRC resources in
the same region.

**Object Lock mode: COMPLIANCE, not GOVERNANCE.** GOVERNANCE mode allows a
sufficiently-privileged principal to shorten or remove a retention lock,
which defeats the point of an evidence vault an assessor is supposed to
trust unconditionally. COMPLIANCE mode is not reversible by anyone,
including the account root, until the retention period (400 days) expires.
The stricter choice costs nothing at this scale and matches what "real
evidence" should mean.

**KMS deletion window: 30 days, not the 7-day minimum.** This CMK is the
custody root for PHI and evidence: it encrypts the S3 uploads bucket, the
DynamoDB table, the evidence vault, and the project's own Terraform state.
Because a key's pending deletion makes everything it encrypts
unrecoverable, the longer window trades a slower key teardown (negligible
cost at this scale) for more room to notice and cancel an accidental
deletion request before it's irreversible.

**One shared CMK, not a key per resource.** S3 uploads, DynamoDB, the
evidence vault, and Terraform state all encrypt under the same capstone
CMK rather than four separate keys. That's a smaller key-policy surface to
manage and reason about, but it also means those resources share a single
blast radius: revoking or rotating the key affects all of them at once,
and any principal granted `kms:Decrypt` on the key can read all of them,
not just one. Per-resource CMKs would isolate that blast radius (the
better posture for production PHI) but multiply the key-policy surface
for a capstone-scale build. CloudTrail's log bucket deliberately stays on
AES256 instead of this CMK (see `cloudtrail.tf`), which is the one place
the sharing was declined rather than defaulted into.

**Account structure: single AWS account.** The workload, the evidence
vault, and the CI role's OIDC trust all live in one account. A second,
dedicated account for the evidence vault would separate the systems an
assessor needs to trust from the systems being assessed, which is the
cleaner architecture, but stands up an AWS Organization, cross-account
IAM, and a second Terraform backend for a capstone with a multi-day
budget. Single-account is named explicitly as acceptable for this
timeframe, not as the right long-term answer.

**Pipeline apply gate: auto-apply on merge, no manual approval step.**
`terraform plan` and the Conftest policy gate both run and must pass
before a PR can merge: the gate that matters (does this change violate a
closed gap) already happens pre-merge. A manual approval step between
merge and apply would add a second checkpoint after the one that actually
enforces anything, which is friction without a corresponding safety gain
at this scale. It's a defensible choice, not the only correct one. See
"what I'd do with another sprint" below.

**Gateway VPC Endpoints instead of a NAT Gateway (found during Layer 1
planning, not planned in advance).** The starter's private subnets had no
route out at all: no NAT Gateway, no default route, nothing. Moving the
Lambda into them for GAP-05 would have cut off its only two AWS calls
(`dynamodb:PutItem`, `s3:PutObject`). Rather than add a NAT Gateway
(cost, and a 0.0.0.0/0 egress path that undercuts the point of the
boundary control), `vpc_endpoints.tf` adds gateway-type VPC endpoints for
S3 and DynamoDB, and the Lambda's security group egress is scoped to those
endpoints' prefix lists on port 443. The result is a tighter closure of
SC.L2-3.13.1 than the brief's literal ask: the function has no internet
egress path at all, not just a private IP.

**CI role IAM policy is service-scoped, not fully resource-ARN-scoped
(Layer 3, named in `terraform/github_oidc.tf`'s own header comment).** The
`grc_gate_ci` role's policy is resource-name-prefix-scoped everywhere
AWS's IAM condition and resource syntax supports it (S3 buckets, IAM
roles, log groups, the KMS key), but several actions (VPC, subnet, route
table, security group, Lambda, and API Gateway management) are granted at
`Resource = "*"` because those services either don't support
resource-level permissions at plan/apply time or don't expose a
name-prefix condition key that would let Terraform's `plan` step work
without knowing resource IDs that don't exist yet. Naming every VPC
endpoint and Lambda alias explicitly would be more precise, but was traded
for shipping a working end-to-end pipeline in the capstone's timeframe.
This is worth flagging to an assessor directly rather than letting it
surface as a finding: the role can create and modify any VPC, subnet, or
Lambda function in the account, not just this project's.

**GAP-04's control mapping is an interpretation, not a literal text
match.** `SP_800_171_03.08.09`'s actual catalog title is "System Backup –
Cryptographic Protection," which is about backup encryption, not
protection from accidental overwrite. S3 versioning on the uploads bucket
is mapped there because it's the closest fit in the 03.08.x
(media-protection) family, a storage-native recovery mechanism sitting
in the same control family as formal backup, not a formal backup process
itself. The component definition's own `description` for that
implemented-requirement says this explicitly rather than presenting a
one-sentence claim that wouldn't survive a control-text comparison.

## What I'd do with another sprint

- Close GAP-06 and GAP-08 in Terraform + a matching Rego policy each.
- Tighten the CI role's IAM policy from service-level to full resource-ARN
  scoping.
- Add a manual-approval gate between the policy check and apply, per the
  brief's own "acceptable alternative" framing (auto-apply-on-merge was
  chosen for consistency with this vault's prior lab pattern, not because
  it's strictly better).
- Extend GAP-03's Rego policy from existence-only to content-verifying
  (parsing the rendered bucket policy JSON), matching what GAP-07's policy
  already does, now that the underlying values are always known post-Layer-1-apply.

## What I didn't get to

- **A second AWS account for the evidence vault.** Named above as an
  acceptable-for-now trade-off, not the cleaner option. The vault and the
  workload it's evidencing currently share a trust boundary.
- **CloudTrail data events on the uploads bucket.** `terraform/cloudtrail.tf`
  configures a multi-region trail with log-file validation, but only
  management events: no `event_selector` or `advanced_event_selector`
  block exists for S3 object-level (data) events. An assessor relying on
  this trail as evidence for who read or wrote a specific PHI object in
  the uploads bucket won't find that in CloudTrail today; only the
  management-plane actions (bucket policy changes, IAM changes, and
  similar) are captured. Layer 4's OSCAL cites this trail as supporting
  context for the audit-record-generation story, so this gap is worth
  naming plainly rather than letting an assessor discover it.
- **Frontend, API-layer authentication (Cognito), multi-region failover,
  and patient-data lifecycle management (deletion/export).** All out of
  scope per the starter's own `WORKLOAD.md` (not this capstone's job to
  build) but worth naming as known gaps in the system as a whole, not
  just this baseline's remit.
- **GAP-06 and GAP-08**, covered above.
