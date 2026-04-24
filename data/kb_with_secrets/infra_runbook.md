# Infra Runbook (RESTRICTED — SRE only)

> Synthetic credentials for demo purposes. Do not use against real systems.

## Production AWS

- Account: `acme-prod-000111222333`
- `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`
- `AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
- MFA device: arn:aws:iam::000111222333:mfa/oncall

## Database

- Host: `db-prod.acme.internal`
- Admin user: `ops_admin`
- Admin password: `Pr0d-R0tate-Me-2026!`

## Third-party

- `STRIPE_LIVE_KEY=[REDACTED]`
- `OPENAI_API_KEY_PROD=[REDACTED]`

## Paging

- PagerDuty escalation policy ID: P1A2B3C
- Oncall contact: Alex Rivera (+1-555-0133)
