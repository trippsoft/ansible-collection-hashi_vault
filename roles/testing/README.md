<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.testing
Version: 1.1.2

This role configures Hashicorp Vault in development mode for use in Molecule testing.

## Requirements

| Platform | Versions |
| -------- | -------- |
| Debian | <ul><li>bullseye</li><li>bookworm</li></ul> |
| EL | <ul><li>8</li><li>9</li></ul> |
| Ubuntu | <ul><li>focal</li><li>jammy</li><li>noble</li></ul> |

## Dependencies

| Collection |
| ---------- |
| ansible.posix |

## Role Arguments
|Option|Description|Type|Required|Choices|Default|
|---|---|---|---|---|---|
| vault_token | The token to use for authenticating to Vault. | str | yes |  |  |
| vault_listen_address | The address on which Vault will listen. | str | no |  | {{ vault_ip_address }} |
| vault_listen_port | The port on which Vault will listen. | int | no |  | 8200 |
| vault_configure_firewalld | Whether to configure firewalld. If Debian-based, this will default to false. If Red Hat-based, this will default to true. | bool | no |  | true |
| vault_configure_ufw | Whether to configure ufw. If Debian-based, this will default to true. If Red Hat-based, this will default to false. | bool | no |  | true |
| vault_ip_address | The IP address of the host on which Vault is running. | str | no |  | {{ ansible_host }} |


## License
MIT

## Author and Project Information
Jim Tarpley
<!-- END_ANSIBLE_DOCS -->
