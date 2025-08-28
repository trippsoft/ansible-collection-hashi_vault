# Changelog

All notable changes to this project will be documented in this file.

## [1.10.4] - 2025-08-28

### Role - install

- Added support for Prometheus metrics.

## [1.10.3] - 2025-06-11

### Collection

- Changed repository URL to use GitHub Organization.
- Corrected missing or extra dependencies.

## [1.10.2] - 2025-05-15

### Role - install

- Changed OS validation.

## [1.10.1] - 2025-05-14

### Module Plugin - vault_ssh_sign_public_key

- Added signing public key to the module output.

## [1.10.0] - 2025-05-07

### Collection

- *vault_ssh_ca_role* module plugin added.
- *vault_ssh_ca_signing_key* module plugin added.
- *vault_ssh_otp_role* module plugin added.
- *vault_ssh_secret_engine* module plugin added.
- *vault_ssh_sign_public_key* module plugin added.

## [1.9.0] - 2025-02-28

### Collection

- *install* role added.
- *vault_init* module plugin added.
- *vault_unseal* module plugin added.

## [1.8.1] - 2025-02-25

### Module Plugin - vault_pki_secret_engine

- Fixed a bug that caused PKI secret engines that aren't configured to not accept a signed intermediate CA certificate.

## [1.8.0] - 2025-02-25

### Collection

- *vault_pki_sign_intermediate* module plugin added.

## [1.7.0] - 2025-02-20

### Role - signed_certificate

- Added support for Nobara Linux to allow for local testing of the role in certain contexts.
- Removed all support for CSR to file.  If this is needed, copy the contents of `cert_csr_content` to a file using a task.

## [1.6.0] - 2025-02-19

### Role - signed_certificate

- Restructured role to match *trippsc2.general.generate_csr* role and make writing certificate to file optional.

## [1.5.0] - 2025-02-13

### Collection

- *vault* action group added for all **community.hashi_vault** collection module plugins and all **trippsc2.hashi_vault** collection module plugins. This was done to allow for shared default connection arguments to supplied for both collections.
- *vault_pki_generate_intermediate_csr* module plugin added.
- *vault_pki_set_signed_intermediate* module plugin added.
- Revised collection README documentation.

### Module Plugin - vault_database_secret_engine

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_database_static_role

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_kv1_secret_engine

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_kv2_secret_engine

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_pki_role

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_pki_root_ca_certificate

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_pki_secret_engine

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

### Module Plugin - vault_pki_sign_verbatim

- Made several code quality and style changes to the module that were recommended by the Ansible sanity tests.
- Revised plugin documentation.

## [1.4.3] - 2025-01-08

### Collection

- Added Changelog.
- Updated collection README documentation.

### Module Plugin - vault_kv2_secret_engine

- Fixed the module documentation copied from another module and not changed.

### Module Plugin - vault_pki_role

- Fixed the module documentation copied from another module and not changed.

## [1.4.2] - 2024-08-09

### Collection

- Minimum Ansible version changed from `2.14` to `2.15` due to EOL status.

## [1.4.1] - 2024-08-03

### Role - signed_certificate

- Added validation for `cert_certificate_owner`, `cert_certificate_group`, `cert_ca_chain_owner`, and `cert_ca_chain_group` variables.

## [1.4.0] - 2024-07-26

### Collection

- Changed version requirement for **trippsc2.general** collection dependency from `>=2.0.0` to `>=2.4.0`.

### Role - signed_certificate

- Removed defaults for the `cert_private_key_path`, `cert_certificate_path`, and `cert_ca_chain_path` variables and made them required to prevent unexpected behavior.

## [1.3.8] - 2024-07-12

### Role - signed_certificate

- Added the `vault_url` and `vault_token` variables to the role argument spec.
- Updated documentation and role metadata for readability.
- Added validation where possible.

## [1.3.7] - 2024-07-08

### Collection

- Updated manifest file to ensure that molecule tests are not included in releases.

### Role - signed_certificate

- Added step to add the `cert_private_key_owner` user to the `ssl-cert` group on Debian-based machines.

## [1.3.6] - 2024-07-02

### Role - testing_ca

- Added missing step to save the CA certificate to a file before copying it, fixing a breaking bug.

## [1.3.5] - 2024-07-02

### Role - testing_ca

- Added steps to copy the CA certificate to the system certificate authority bundle.

## [1.3.4] - 2024-06-30

### Role - testing_ca

- Fixed documentation to properly include role dependencies.

## [1.3.3] - 2024-06-30

### Role - signed_certificate

- Changed references to Red Hat Enterprise Linux (RHEL) to more accurately reference Enterprise Linux (EL) to convey the intention to support derivatives (Rocky/AlmaLinux/etc.)

### Role - testing

- Changed references to Red Hat Enterprise Linux (RHEL) to more accurately reference Enterprise Linux (EL) to convey the intention to support derivatives (Rocky/AlmaLinux/etc.)

## [1.3.1] - 2024-06-28

### Role - signed_certificate

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

### Module Plugin - vault_database_secret_engine

- Refactored module to allow for code reuse.

### Module Plugin - vault_kv1_secret_engine

- Refactored module to allow for code reuse.

### Module Plugin - vault_kv2_secret_engine

- Refactored module to allow for code reuse.

### Module Plugin - vault_pki_secret_engine

- Refactored module to allow for code reuse.

## [1.1.3] - 2024-06-20

### Role - testing

- Updated documentation and role metadata for readability.

## [1.1.2] - 2024-06-11

### Collection

- Initial release.
- *vault_database_secret_engine* module plugin added.
- *vault_kv1_secret_engine* module plugin added.
- *vault_kv2_secret_engine* module plugin added.
- *vault_pki_secret_engine* module plugin added.
- *testing* role added.
