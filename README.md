# Ansible Collection: trippsc2.hashi_vault

This collection extends the community.hashi_vault collection with additional functionality.

## Content

### Module plugins

- [vault_database_secret_engine](plugins/modules/vault_database_secret_engine.py) - Configures a Database secret engine in HashiCorp Vault
- [vault_database_static_role](plugins/modules/vault_database_static_role.py) - Configures a Database static role in HashiCorp Vault
- [vault_kv1_secret_engine](plugins/modules/vault_kv1_secret_engine.py) - Configures a KV version 1 secret engine in HashiCorp Vault
- [vault_kv2_secret_engine](plugins/modules/vault_kv2_secret_engine.py) - Configures a KV version 2 secret engine in HashiCorp Vault
- [vault_pki_generate_intermediate_csr](plugins/modules/vault_pki_generate_intermediate_csr.py) - Generates an certificate signing request (CSR) for a PKI secret engine
- [vault_pki_role](plugins/modules/vault_pki_role.py) - Configures a PKI secret engine role in HashiCorp Vault
- [vault_pki_root_ca_certificate](plugins/modules/vault_pki_root_ca_certificate.py) - Configures a PKI root CA certificate in HashiCorp Vault
- [vault_pki_secret_engine](plugins/modules/vault_pki_secret_engine.py) - Configures a PKI secret engine in HashiCorp Vault
- [vault_pki_set_signed_intermediate_csr](plugins/modules/vault_pki_set_signed_intermediate_csr.py) - Sets a signed intermediate CA certificate for a PKI secret engine
- [vault_pki_sign_intermediate](plugins/modules/vault_pki_sign_intermediate.py) - Signs a certificate signing request as an intermediate CA in HashiCorp Vault
- [vault_pki_sign_verbatim](plugins/modules/vault_pki_sign_verbatim.py) - Signs a certificate signing request verbatim in HashiCorp Vault
- [vault_ssh_ca_role](plugins/modules/vault_ssh_ca_role.py) - Configures an SSH CA role in HashiCorp Vault
- [vault_ssh_ca_signing_key](plugins/modules/vault_ssh_ca_signing_key.py) - Configure SSH CA signing key in HashiCorp Vault
- [vault_ssh_otp_role](plugins/modules/vault_ssh_otp_role.py) - Configures an SSH one-time-password role in HashiCorp Vault
- [vault_ssh_secret_engine](plugins/modules/vault_ssh_secret_engine.py) - Configures an SSH secret engine in HashiCorp Vault
- [vault_ssh_sign_public_key](plugins/modules/vault_ssh_sign_public_key.py) - Signs an SSH public key with an SSH CA role in HashiCorp Vault
- [vault_unseal](plugins/modules/vault_unseal.py) - Unseals a HashiCorp Vault instance

### Roles

- [install](roles/install/README.md) - This role installs and configures HashiCorp Vault.
- [signed_certificate](roles/signed_certificate/README.md) - This role signs a certificate using Hashicorp Vault.
- [testing](roles/testing/README.md) - This role configures Hashicorp Vault in development mode for use in Molecule testing.
- [testing_ca](roles/testing_ca/README.md) - This role configures Hashicorp Vault in development mode for use in Molecule testing as a Certification Authority.
