<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.signed_certificate
Version: 1.3.6

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
| cert_certificate_owner | <p>The owner of the certificate on Linux systems.</p> | str | no |  | root |
| cert_certificate_group | <p>The group of the certificate on Linux systems.</p> | str | no |  | root |
| cert_certificate_mode | <p>The mode of the certificate on Linux systems.</p> | str | no |  | 0644 |
| cert_vault_mount_point | <p>The mount point for the PKI secrets engine in Vault.</p> | str | no |  | pki |
| cert_vault_role | <p>The role to use for signing the certificate in Vault.</p> | str | no |  | verbatim |
| cert_copy_ca_chain | <p>Whether to copy the CA chain to the expected path.</p> | bool | no |  | false |
| cert_ca_chain_path | <p>The path to copy the CA chain.</p><p>On Debian-based systems, this is defaults /usr/local/share/ca-certificates/ca_chain.crt.</p><p>On EL systems, this is defaults /etc/pki/ca-trust/source/anchors/ca_chain.crt.</p><p>On Windows systems, this is defaults C:\Windows\Temp\ca_chain.crt.</p> | str | no |  | OS specific |
| cert_ca_chain_owner | <p>The owner of the CA chain on Linux systems.</p> | str | no |  | root |
| cert_ca_chain_group | <p>The group of the CA chain on Linux systems.</p> | str | no |  | root |
| cert_ca_chain_mode | <p>The mode of the CA chain on Linux systems.</p> | str | no |  | 0644 |
| cert_update_ca_trust | <p>Whether to run the command to update the CA trust on Linux systems, if the CA chain is copied.</p> | bool | no |  | true |


## License
MIT

## Author and Project Information
Jim Tarpley
<!-- END_ANSIBLE_DOCS -->
