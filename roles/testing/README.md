<!-- BEGIN_ANSIBLE_DOCS -->

# Ansible Role: trippsc2.hashi_vault.testing
Version: 1.3.3

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
| vault_token | <p>The token to use for authenticating to Vault.</p> | str | yes |  |  |
| vault_listen_address | <p>The address on which Vault will listen.</p> | str | no |  | {{ vault_ip_address }} |
| vault_listen_port | <p>The port on which Vault will listen.</p> | int | no |  | 8200 |
| vault_configure_firewalld | <p>Whether to configure firewalld.</p><p>For EL and Debian systems, this will default to true.</p><p>For Ubuntu systems, this will default to false.</p> | bool | no |  | true |
| vault_configure_ufw | <p>Whether to configure ufw.</p><p>For Ubuntu systems, this will default to true.</p><p>For EL and Debian systems, this will default to false.</p> | bool | no |  | true |
| vault_ip_address | <p>The IP address of the host on which Vault is running.</p> | str | no |  | {{ ansible_host }} |


## License
MIT

## Author and Project Information
Jim Tarpley
<!-- END_ANSIBLE_DOCS -->
