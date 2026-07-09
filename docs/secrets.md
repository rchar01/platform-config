# Secrets

Secret handling is documented in [Private Workflow](private-workflow.md#secrets).

Short rule: do not commit real secrets to `platform-config` or private Git. Real non-secret operational configuration belongs in `../platform-private/config/`; admin kubeconfigs, tokens, private keys, passwords, and other secrets belong under `~/.config/platform-infrastructure/` or another outside-Git secret store.
