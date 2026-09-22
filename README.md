# Quanto-Vault

a Post Quantum encryption service.

## Bootstrap status

This repository now includes a basic Go project scaffold with:

- Users identified by public keys (no username/password authentication)
- Groups with user membership
- Secrets scoped to either users or groups
- Key-based challenge/response authentication (default verifier: `ed25519`)
- A pluggable key verifier interface so Open Quantum Safe (`oqs`) verification can be added via `RegisterKeyVerifier`

## Run tests

```bash
go test ./...
```
