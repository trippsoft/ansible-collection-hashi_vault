<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.signed_certificate
Version: 1.10.0

This role signs a certificate using Hashicorp Vault.

## Requirements

| Platform | Versions |
| -------- | -------- |
| Debian | <ul><li>bullseye</li><li>bookworm</li></ul> |
| EL | <ul><li>8</li><li>9</li></ul> |
| Ubuntu | <ul><li>focal</li><li>jammy</li><li>noble</li></ul> |
| Windows | <ul><li>2019</li><li>2022</li></ul> |

## Dependencies
| Role |
| ---- |
| trippsc2.general.generate_csr |

| Collection |
| ---------- |
| ansible.windows |
| trippsc2.general |

## Role Arguments
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| vault_url | <p>The URL for accessing HashiCorp Vault.</p><p>Alternatively, this can be configured through ansible.cfg or environment variables.</p> | str | no |  |  |
| vault_token | <p>The token for accessing HashiCorp Vault.</p><p>Alternatively, this (or any other authentication method) can be configured through ansible.cfg or environment variables.</p> | str | no |  |  |
| cert_certificate_to_file | <p>Whether to write the certificate to a file.</p><p>If `true`, the certificate will be written to the path specified in *cert_certificate_path*.</p> | bool | no |  | True |
| cert_certificate_to_variable | <p>Whether to store the certificate in a variable.</p><p>If `true`, the certificate will be stored in the variable specified in *cert_certificate_variable*.</p> | bool | no |  | False |
| cert_certificate_owner | <p>The owner of the certificate on Linux systems.</p><p>On Windows systems, this is ignored.</p> | str | no |  | root |
| cert_certificate_group | <p>The group of the certificate on Linux systems.</p><p>On Windows systems, this is ignored.</p> | str | no |  | root |
| cert_certificate_mode | <p>The mode of the certificate on Linux systems.</p><p>On Windows systems, this is ignored.</p> | str | no |  | 0644 |
| cert_vault_mount_point | <p>The mount point for the PKI secrets engine in Vault.</p> | str | no |  | pki |
| cert_vault_role | <p>The role to use for signing the certificate in Vault.</p> | str | no |  | verbatim |
| cert_copy_ca_chain | <p>Whether to copy the CA chain to the expected path.</p> | bool | no |  | False |
| cert_ca_chain_path | <p>The path to copy the CA chain.</p><p>If *cert_copy_ca_chain* is `false`, this is ignored.</p><p>If *cert_copy_ca_chain* is `true`, this is required.</p> | str | no |  |  |
| cert_ca_chain_owner | <p>The owner of the CA chain on Linux systems.</p><p>On Windows systems, this is ignored.</p><p>If *cert_copy_ca_chain* is `false`, this is ignored.</p> | str | no |  | root |
| cert_ca_chain_group | <p>The group of the CA chain on Linux systems.</p><p>On Windows systems, this is ignored.</p><p>If *cert_copy_ca_chain* is `false`, this is ignored.</p> | str | no |  | root |
| cert_ca_chain_mode | <p>The mode of the CA chain on Linux systems.</p><p>On Windows systems, this is ignored.</p><p>If *cert_copy_ca_chain* is `false`, this is ignored.</p> | str | no |  | 0644 |
| cert_update_ca_trust | <p>Whether to run the command to update the CA trust on Linux systems, if the CA chain is copied.</p><p>On Windows systems, this is ignored.</p><p>If *cert_copy_ca_chain* is `false`, this is ignored.</p> | bool | no |  | True |


## License
MIT

## Author and Project Information
Jim Tarpley (@trippsc2)
<!-- END_ANSIBLE_DOCS -->
