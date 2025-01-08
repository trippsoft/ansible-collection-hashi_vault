# Ansible Collection: trippsc2.hashi_vault

This collection extends the community.hashi_vault collection with additional functionality.

## Content

### Module plugins

- vault_database_secret_engine - Configures a Database secret engine in HashiCorp Vault.
- vault_database_static_role - Configures a Database static role in HashiCorp Vault.
- vault_kv1_secret_engine - Configures a KV version 1 secret engine in HashiCorp Vault.
- vault_kv2_secret_engine - Configures a KV version 2 secret engine in HashiCorp Vault.
- vault_pki_role - Configures a PKI secret engine role in HashiCorp Vault.
- vault_pki_root_ca_certificate - Configures a PKI secret engine root CA certificate in HashiCorp Vault.
- vault_pki_secret_engine - Configures a PKI secret engine in HashiCorp Vault.
- vault_pki_sign_verbatim - Signs a certificate signing request (CSR) verbatim in HashiCorp Vault.

### Roles

- [signed_certificate](roles/signed_certificate/README.md) - This role signs a certificate using Hashicorp Vault.
- [testing](roles/testing/README.md) - This role configures Hashicorp Vault in development mode for use in Molecule testing.
- [testing_ca](roles/testing_ca/README.md) - This role configures Hashicorp Vault in development mode for use in Molecule testing as a Certification Authority.
