# Private Configuration

Private configuration is documented in [Private Workflow](private-workflow.md).

Short rule: `platform-config` contains public Ansible code and safe examples only. Real inventories, variables, access policies, CA certificates, and non-secret environment config belong in `../platform-private/config/`; real kubeconfigs, tokens, private keys, passwords, and other secrets belong outside Git.
