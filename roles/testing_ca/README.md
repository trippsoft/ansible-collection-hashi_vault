<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.testing_ca
Version: 1.10.1

This role configures Hashicorp Vault in development mode for use in Molecule testing as a Certification Authority.

## Requirements

| Platform | Versions |
| -------- | -------- |
| Debian | <ul><li>bullseye</li><li>bookworm</li></ul> |
| EL | <ul><li>8</li><li>9</li></ul> |
| Ubuntu | <ul><li>focal</li><li>jammy</li><li>noble</li></ul> |

## Dependencies
| Role |
| ---- |
| trippsc2.hashi_vault.testing |

| Collection |
| ---------- |
| ansible.posix |

## Role Arguments
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| vault_url | <p>The URL to use for accessing Vault.</p> | str | no |  | http://{{ vault_listen_address }}:{{ vault_listen_port }} |
| vault_token | <p>The token to use for authenticating to Vault.</p> | str | yes |  |  |
| vault_listen_address | <p>The address on which Vault will listen.</p> | str | no |  | {{ vault_ip_address }} |
| vault_listen_port | <p>The port on which Vault will listen.</p> | int | no |  | 8200 |
| vault_ip_address | <p>The IP address of the host on which Vault is running.</p> | str | no |  | {{ ansible_host }} |


## License
MIT

## Author and Project Information
Jim Tarpley (@trippsc2)
<!-- END_ANSIBLE_DOCS -->
