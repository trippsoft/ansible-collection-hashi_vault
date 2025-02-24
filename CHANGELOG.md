# Changelog

All notable changes to this project will be documented in this file.

## [1.8.0] - 2025-02-20

### Collection

- *vault_pki_sign_intermediate* module plugin added.

## [1.7.0] - 2025-02-20

### signed_certificate Role

- Added support for Nobara Linux to allow for local testing of the role in certain contexts.
- Removed all support for CSR to file.  If this is needed, copy the contents of `cert_csr_content` to a file using a task.

## [1.6.0] - 2025-02-19

### signed_certificate Role

- Restructured role to match *trippsc2.general.generate_csr* role and make writing certificate to file optional.

## [1.5.0] - 2025-02-13

### Collection

- *vault* action group added for all **community.hashi_vault** collection module plugins and all **trippsc2.hashi_vault** collection module plugins. This was done to allow for shared default connection arguments to supplied for both collections.
- *vault_pki_generate_intermediate_csr* module plugin added.
- *vault_pki_set_signed_intermediate* module plugin added.
- Revised collection README documentation.

### vault_database_secret_engine Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_database_static_role Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_kv1_secret_engine Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_kv2_secret_engine Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_pki_role Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_pki_root_ca_certificate Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_pki_secret_engine Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### vault_pki_sign_verbatim Module plugin

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

## [1.4.3] - 2025-01-08

### Collection

- Added Changelog.
- Updated collection README documentation.

### vault_kv2_secret_engine Module plugin

- Fixed the module documentation copied from another module and not changed.

### vault_pki_role Module plugin

- Fixed the module documentation copied from another module and not changed.

## [1.4.2] - 2024-08-09

### Collection

- Minimum Ansible version changed from `2.14` to `2.15` due to EOL status.

## [1.4.1] - 2024-08-03

### signed_certificate Role

- Added validation for `cert_certificate_owner`, `cert_certificate_group`, `cert_ca_chain_owner`, and `cert_ca_chain_group` variables.

## [1.4.0] - 2024-07-26

### Collection

- Changed version requirement for **trippsc2.general** collection dependency from `>=2.0.0` to `>=2.4.0`.

### signed_certificate Role

- Removed defaults for the `cert_private_key_path`, `cert_certificate_path`, and `cert_ca_chain_path` variables and made them required to prevent unexpected behavior.

## [1.3.8] - 2024-07-12

### signed_certificate Role

- Added the `vault_url` and `vault_token` variables to the role argument spec.
- Updated documentation and role metadata for readability.
- Added validation where possible.

## [1.3.7] - 2024-07-08

### Collection

- Updated manifest file to ensure that molecule tests are not included in releases.

### signed_certificate Role

- Added step to add the `cert_private_key_owner` user to the `ssl-cert` group on Debian-based machines.

## [1.3.6] - 2024-07-02

### testing_ca Role

- Added missing step to save the CA certificate to a file before copying it, fixing a breaking bug.

## [1.3.5] - 2024-07-02

### testing_ca Role

- Added steps to copy the CA certificate to the system certificate authority bundle.

## [1.3.4] - 2024-06-30

### testing_ca Role

- Fixed documentation to properly include role dependencies.

## [1.3.3] - 2024-06-30

### signed_certificate Role

- Changed references to Red Hat Enterprise Linux (RHEL) to more accurately reference Enterprise Linux (EL) to convey the intention to support derivatives (Rocky/AlmaLinux/etc.)

### testing Role

- Changed references to Red Hat Enterprise Linux (RHEL) to more accurately reference Enterprise Linux (EL) to convey the intention to support derivatives (Rocky/AlmaLinux/etc.)

## [1.3.1] - 2024-06-28

### signed_certificate Role

- Fixed short description of role.

## [1.3.0] - 2024-06-28

### Collection

- *vault_database_static_role* module plugin added.

## [1.2.0] - 2024-06-27

### Collection

- *vault_pki_role* module plugin added.
- *vault_pki_root_ca_certificate* module plugin added.
- *vault_pki_sign_verbatim* module plugin added.
- *signed_certificate* role added.
- *testing_ca* role added.

### vault_database_secret_engine Module plugin

- Refactored module to allow for code reuse.

### vault_kv1_secret_engine Module plugin

- Refactored module to allow for code reuse.

### vault_kv2_secret_engine Module plugin

- Refactored module to allow for code reuse.

### vault_pki_secret_engine Module plugin

- Refactored module to allow for code reuse.

## [1.1.3] - 2024-06-20

### testing Role

- Updated documentation and role metadata for readability.

## [1.1.2] - 2024-06-11

### Collection

- Initial release.
- *vault_database_secret_engine* module plugin added.
- *vault_kv1_secret_engine* module plugin added.
- *vault_kv2_secret_engine* module plugin added.
- *vault_pki_secret_engine* module plugin added.
- *testing* role added.
