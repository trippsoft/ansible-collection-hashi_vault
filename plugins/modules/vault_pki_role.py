#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import hvac.exceptions
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_role
version_added: 1.2.0
author:
  - Jim Tarpley
short_description: Configures a PKI secret engine role in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Ensures that a PKI secret engine role is configured in HashiCorp Vault.
attributes:
  check_mode:
    support: full
    details:
      - This module supports check mode.
extends_documentation_fragment:
  - trippsc2.hashi_vault.attributes
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.engine_mount
options:
  name:
    type: str
    required: true
    description:
      - The name of the role to manage.
  state:
    type: str
    default: present
    choices:
      - present
      - absent
    description:
      - Whether the role should be present or absent.
  ttl:
    type: str
    required: false
    description:
      - The default Time-To-Live value for issued certificates from this role.
      - This can be specified as a string duration with time suffix or as an integer number of seconds.
      - If not set, uses the system default value or the value of `max_ttl`, whichever is shorter, on new roles.
  max_ttl:
    type: str
    required: false
    description:
      - The maximum Time-To-Live value for issued certificates from this role.
      - This can be specified as a string duration with time suffix or as an integer number of seconds.
      - If not set, defaults to the system maximum lease TTL on new roles.
  allow_localhost:
    type: bool
    required: false
    description:
      - Whether clients can request certificates for `localhost` as one of the requested common names.
      - This is useful for testing and to allow clients on a single host to talk securely.
      - This is allowed by default, if not set on new roles.
  allowed_domains:
    type: list
    required: false
    elements: str
    description:
      - The domains for which this role can issue certificates.
      - This is used with the `allow_bare_domains` and `allow_subdomains` options.
      - If not set, the role can issue certificates for any domain on new roles.
  allowed_domains_template:
    type: bool
    required: false
    description:
      - Whether the `allowed_domains` list can use templates.
      - This is not enabled by default, if not set on new roles.
  allow_bare_domains:
    type: bool
    required: false
    description:
      - Whether clients can request certificates matching the value of the actual domains themselves.
      - e.g. If a configured domain set with `allowed_domains` is `example.com`, this allows clients to
        actually request a certificate containing the name `example.com` as one of the DNS values on the
        final certificate. In some scenarios, this can be considered a security risk.
      - This is not allowed by default, if not set on new roles.
  allow_subdomains:
    type: bool
    required: false
    description:
      - Whether clients can request certificates with CNs that are subdomains of the CNs allowed by
        the other role options. This includes wildcard subdomains.
      - For example, an `allowed_domains` value of `example.com` with this option set to true will allow
        `foo.example.com` and `bar.example.com` as well as `*.example.com`.
      - This is redundant when using the `allow_any_name` option.
      - This is not allowed by default, if not set on new roles.
  allow_glob_domains:
    type: bool
    required: false
    description:
      - Allows names specified in `allowed_domains` to contain glob patterns (e.g. `ftp*.example.com`)
      - Clients will be allowed to request certificates with names matching the glob patterns.
      - This is not allowed by default, if not set on new roles.
  allow_wildcard_certificates:
    type: bool
    required: false
    description:
      - Whether clients can request wildcard certificates.
      - This is allowed by default, if not set, on new roles.
  allow_any_name:
    type: bool
    required: false
    description:
      - Whether clients can request a certificate CN that is not in the `allowed_domains` list.
      - Useful in some circumstances, but make sure you understand whether it is appropriate for your
        installation before enabling it.
      - This is not allowed by default, if not set on new roles.
  enforce_hostnames:
    type: bool
    required: false
    description:
      - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
        addresses.
      - This is enforced by default, if not set on new roles.
  allow_ip_sans:
    type: bool
    required: false
    description:
      - Whether clients can request IP Subject Alternative Names.
      - No authorization checking is performed except to verify that the given values are valid IP
        addresses.
      - This is allowed by default, if not set on new roles.
  allowed_uri_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of allowed URI Subject Alternative Names
      - No authorization checking is performed except to verify that the given values are valid URIs
      - Values can contain glob patterns (e.g. `spiffe://hostname/*`).
      - This defaults to an empty list, if not set on new roles.
  allowed_uri_sans_template:
    type: bool
    required: false
    description:
      - Whether the `allowed_uri_sans` list can use templates.
      - This is disabled by default, if not set on new roles.
  allowed_other_sans:
    type: list
    required: false
    elements: str
    description:
      - Defines allowed custom OID/UTF8-string SANs
      - This can be a comma-delimited list or a JSON string slice, where each element has the same format
        as OpenSSL `<oid>;<type>:<value>`, but the only valid type is `UTF8` or `UTF-8`
      - The `value` part of an element may be a `*` to allow any value with that OID
      - Alternatively, specifying a single `*` will allow any `other_sans` input. `server_flag`
        `(bool)` Specifies if certificates are flagged for server use.
      - This defaults to an empty list, if not set on new roles.
  server_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for server use.
      - This is enabled by default, if not set on new roles.
  client_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for client use.
      - This is enabled by default, if not set on new roles.
  code_signing_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for code signing use.
      - This is disabled by default, if not set on new roles.
  email_protection_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for email protection use.
      - This is disabled by default, if not set on new roles.
  key_type:
    type: str
    required: false
    choices:
      - rsa
      - ec
      - any
    description:
      - Specifies the type of key to generate for generated private keys and the type of key expected for
        submitted CSRs
      - Currently, `rsa` and `ec` are supported, or when signing CSRs `any` can be specified to allow
        keys of either type and with any bit size (subject to > 1024 bits for RSA keys).
      - This defaults to `rsa`, if not set on new roles.
  key_bits:
    type: int
    required: false
    description:
      - Specifies the number of bits to use for the generated keys
      - This defaults to 2048 for RSA keys and 256 for EC keys, if not set on new roles.
  signature_bits:
    type: int
    required: false
    description:
      - Specifies the number of bits to use for the generated signature.
      - This only applies to RSA keys.
      - This defaults to 256, if not set on new roles.
  use_pss:
    type: bool
    required: false
    description:
      - Whether to use the Probabilistic Signature Scheme (PSS) for RSA keys.
      - This defaults to false, if not set on new roles.
  key_usage:
    type: list
    required: false
    elements: str
    choices:
      - DigitalSignature
      - ContentCommitment
      - KeyEncipherment
      - DataEncipherment
      - KeyAgreement
      - CertSign
      - CRLSign
      - EncipherOnly
      - DecipherOnly
    description:
      - The list of allowed key usage constraints on issued certificates.
      - To specify no key usage constraints, set this to an empty list.
      - This defaults to `DigitalSignature`, `KeyAgreement`, and `KeyEncipherment`, if not set on new roles.
  ext_key_usage:
    type: list
    required: false
    elements: str
    choices:
      - ServerAuth
      - ClientAuth
      - CodeSigning
      - EmailProtection
      - IPSECEndSystem
      - IPSECTunnel
      - IPSECUser
      - TimeStamping
      - OCSPSigning
      - MicrosoftServerGatedCrypto
      - NetscapeServerGatedCrypto
      - MicrosoftCommercialCodeSigning
      - MicrosoftKernelCodeSigning
    description:
      - The list of allowed extended key usage constraints on issued certificates.
      - To specify no key usage constraints, set this to an empty list.
      - This defaults to an empty list, if not set on new roles.
  ext_key_usage_oids:
    type: list
    required: false
    elements: str
    description:
      - A list of extended key usage oids.
      - This defaults to an empty list, if not set on new roles.
  use_csr_common_name:
    type: bool
    required: false
    description:
      - Whether the CSR common name is used, when signing a CSR.
      - This has no effect when generating a certificate without a CSR.
      - This is enabled by default, if not set on new roles.
  use_csr_sans:
    type: bool
    required: false
    description:
      - Whether the CSR Subject Alternative Names (SANs) are used, when signing a CSR.
      - This has no effect when generating a certificate without a CSR.
      - This is enabled by default, if not set on new roles.
  ou:
    type: list
    required: false
    elements: str
    description:
      - The list of OU (OrganizationalUnit) values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  organization:
    type: list
    required: false
    elements: str
    description:
      - The list of O (Organization) values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  country:
    type: list
    required: false
    elements: str
    description:
      - The list of C (Country) values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  locality:
    type: list
    required: false
    elements: str
    description:
      - The list of L (Locality) values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  province:
    type: list
    required: false
    elements: str
    description:
      - The list of ST (Province) values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  street_address:
    type: list
    required: false
    elements: str
    description:
      - The list of Street Address values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  postal_code:
    type: list
    required: false
    elements: str
    description:
      - The list of Postal Code values in the subject field of issued certificates.
      - This defaults to an empty list, if not set on new roles.
  generate_lease:
    type: bool
    required: false
    description:
      - Whether certificates issued/signed against this role will have Vault leases attached to them.
      - Certificates can be added to the CRL by `vault revoke <lease_id>` when certificates are
        associated with leases.
      - It can also be done using the `pki/revoke` endpoint.
      - However, when lease generation is disabled, invoking `pki/revoke` would be the only way to add
        the certificates to the CRL.
      - This is disabled by default, if not set on new roles.
  no_store:
    type: bool
    required: false
    description:
      - Whether certificates issued/signed against this role should be stored in the storage backend.
      - This can improve performance when issuing large numbers of certificates.
      - However, certificates issued in this way cannot be enumerated or revoked, so this option is
        recommended only for certificates that are non-sensitive, or extremely short-lived.
      - This option implies a value of `false` for `generate_lease`.
      - This is disabled by default, if not set on new roles.
  require_cn:
    type: bool
    required: false
    description:
      - If set to false, makes the `common_name` field optional while generating a certificate.
      - This is enabled by default, if not set on new roles.
  policy_identifiers:
    type: list
    required: false
    elements: str
    description:
        - A list of policy OIDs.
        - This defaults to an empty list, if not set on new roles.
  basic_constraints_valid_for_non_ca:
    type: bool
    required: false
    description:
      - Whether to mark Basic Constraints valid when issuing non-CA certificates.
      - This is disabled by default, if not set on new roles.
  not_before_duration:
    type: str
    required: false
    description:
      - The duration by which to backdate the NotBefore property.
      - This can be specified as a string duration with time suffix or as an integer number of seconds.
      - This defaults to 30s, if not set on new roles.
  not_after:
    type: str
    required: false
    description:
      - The value of the Not After field on issued certificates.
      - This must be in UTC YYYY-MM-ddTHH:MM:SSZ format.
      - If set to an empty string, the value will be set to the system default.
      - If not set, the value will be set to the system default on new roles.
  allowed_user_ids:
    type: list
    required: false
    elements: str
    description:
      - A list of allowed user IDs.
      - This defaults to an empty list, if not set on new roles.
"""

EXAMPLES = r"""
- name: Create a new PKI role
  trippsc2.hashi_vault.vault_pki_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    name: my-role
    state: present

- name: Remove a PKI role
  trippsc2.hashi_vault.vault_pki_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    name: my-role
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned:
    - success
    - state is C(present)
  description:
    - The configuration of the PKI role.
  sample:
    ttl: 0
    max_ttl: 0
    allow_localhost: true
    allowed_domains: []
    allowed_domains_template: false
    allow_bare_domains: false
    allow_subdomains: false
    allow_glob_domains: false
    allow_wildcard_certificates: true
    allow_any_name: false
    enforce_hostnames: true
    allow_ip_sans: true
    allowed_uri_sans: []
    allowed_uri_sans_template: false
    allowed_other_sans: []
    server_flag: true
    client_flag: true
    code_signing_flag: false
    email_protection_flag: false
    key_type: rsa
    key_bits: 2048
    signature_bits: 256
    use_pss: false
    key_usage:
      - DigitalSignature
      - KeyAgreement
      - KeyEncipherment
    ext_key_usage: []
    ext_key_usage_oids: []
    use_csr_common_name: true
    use_csr_sans: true
    ou: []
    organization: []
    country: []
    locality: []
    province: []
    street_address: []
    postal_code: []
    generate_lease: false
    no_store: false
    require_cn: true
    policy_identifiers: []
    basic_constraints_valid_for_non_ca: false
    not_before_duration: 30
    not_after: ''
    allowed_user_ids: []
  contains:
    ttl:
      type: str
      description:
        - The default Time-To-Live value for issued certificates from this role.
    max_ttl:
      type: str
      description:
        - The maximum Time-To-Live value for issued certificates from this role.
    allow_localhost:
      type: bool
      description:
        - Whether clients can request certificates for `localhost` as one of the requested common names.
    allowed_domains:
      type: list
      elements: str
      description:
        - The domains for which this role can issue certificates.
    allowed_domains_template:
      type: bool
      description:
        - Whether the `allowed_domains` list can use templates.
    allow_bare_domains:
      type: bool
      description:
        - Whether clients can request certificates matching the value of the actual domains themselves.
    allow_subdomains:
      type: bool
      description:
        - Whether clients can request certificates with CNs that are subdomains of the CNs allowed by
          the other role options. This includes wildcard subdomains.
    allow_glob_domains:
      type: bool
      description:
        - Allows names specified in `allowed_domains` to contain glob patterns (e.g. `ftp*.example.com`)
    allow_wildcard_certificates:
      type: bool
      description:
        - Whether clients can request wildcard certificates.
    allow_any_name:
      type: bool
      description:
        - Whether clients can request a certificate CN that is not in the `allowed_domains` list.
    enforce_hostnames:
      type: bool
      description:
        - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
          addresses.
    allow_ip_sans:
      type: bool
      description:
        - Whether clients can request IP Subject Alternative Names.
    allowed_uri_sans:
      type: list
      elements: str
      description:
        - The list of allowed URI Subject Alternative Names
    allowed_uri_sans_template:
      type: bool
      description:
        - Whether the `allowed_uri_sans` list can use templates.
    allowed_other_sans:
      type: list
      elements: str
      description:
        - Defines allowed custom OID/UTF8-string SANs
    server_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for server use.
    client_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for client use.
    code_signing_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for code signing use.
    email_protection_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for email protection use.
    key_type:
      type: str
      description:
        - Specifies the type of key to generate for generated private keys and the type of key expected for
          submitted CSRs
    key_bits:
      type: int
      description:
        - Specifies the number of bits to use for the generated keys
    signature_bits:
      type: int
      description:
        - Specifies the number of bits to use for the generated signature.
    use_pss:
      type: bool
      description:
        - Whether to use the Probabilistic Signature Scheme (PSS) for RSA keys.
    key_usage:
      type: list
      elements: str
      description:
        - The list of allowed key usage constraints on issued certificates.
    ext_key_usage:
      type: list
      elements: str
      description:
        - The list of allowed extended key usage constraints on issued certificates.
    ext_key_usage_oids:
      type: list
      elements: str
      description:
        - A list of extended key usage oids.
    use_csr_common_name:
      type: bool
      description:
        - Whether the CSR common name is used, when signing a CSR.
    use_csr_sans:
      type: bool
      description:
        - Whether the CSR Subject Alternative Names (SANs) are used, when signing a CSR.
    ou:
      type: list
      elements: str
      description:
        - The list of OU (OrganizationalUnit) values in the subject field of issued certificates.
    organization:
      type: list
      elements: str
      description:
        - The list of O (Organization) values in the subject field of issued certificates.
    country:
      type: list
      elements: str
      description:
        - The list of C (Country) values in the subject field of issued certificates.
    locality:
      type: list
      elements: str
      description:
        - The list of L (Locality) values in the subject field of issued certificates.
    province:
      type: list
      elements: str
      description:
        - The list of ST (Province) values in the subject field of issued certificates.
    street_address:
      type: list
      elements: str
      description:
        - The list of Street Address values in the subject field of issued certificates.
    postal_code:
      type: list
      elements: str
      description:
        - The list of Postal Code values in the subject field of issued certificates.
    generate_lease:
      type: bool
      description:
        - Whether certificates issued/signed against this role will have Vault leases attached to them.
    no_store:
      type: bool
      description:
        - Whether certificates issued/signed against this role should be stored in the storage backend.
    require_cn:
      type: bool
      description:
        - If set to false, makes the `common_name` field optional while generating a certificate.
    policy_identifiers:
      type: list
      elements: str
      description:
          - A list of policy OIDs.
    basic_constraints_valid_for_non_ca:
      type: bool
      description:
        - Whether to mark Basic Constraints valid when issuing non-CA certificates.
    not_before_duration:
      type: str
      description:
        - The duration by which to backdate the NotBefore property.
    not_after:
      type: str
      description:
        - The value of the Not After field on issued certificates.
    allowed_user_ids:
      type: list
      elements: str
      description:
        - A list of allowed user IDs.
prev_config:
  type: dict
  returned:
    - success
    - changed
  description:
    - The configuration of the PKI role.
  sample:
    ttl: 0
    max_ttl: 0
    allow_localhost: true
    allowed_domains: []
    allowed_domains_template: false
    allow_bare_domains: false
    allow_subdomains: false
    allow_glob_domains: false
    allow_wildcard_certificates: true
    allow_any_name: false
    enforce_hostnames: true
    allow_ip_sans: true
    allowed_uri_sans: []
    allowed_uri_sans_template: false
    allowed_other_sans: []
    server_flag: true
    client_flag: true
    code_signing_flag: false
    email_protection_flag: false
    key_type: rsa
    key_bits: 2048
    signature_bits: 256
    use_pss: false
    key_usage:
      - DigitalSignature
      - KeyAgreement
      - KeyEncipherment
    ext_key_usage: []
    ext_key_usage_oids: []
    use_csr_common_name: true
    use_csr_sans: true
    ou: []
    organization: []
    country: []
    locality: []
    province: []
    street_address: []
    postal_code: []
    generate_lease: false
    no_store: false
    require_cn: true
    policy_identifiers: []
    basic_constraints_valid_for_non_ca: false
    not_before_duration: 30
    not_after: ''
    allowed_user_ids: []
  contains:
    ttl:
      type: str
      description:
        - The default Time-To-Live value for issued certificates from this role.
    max_ttl:
      type: str
      description:
        - The maximum Time-To-Live value for issued certificates from this role.
    allow_localhost:
      type: bool
      description:
        - Whether clients can request certificates for `localhost` as one of the requested common names.
    allowed_domains:
      type: list
      elements: str
      description:
        - The domains for which this role can issue certificates.
    allowed_domains_template:
      type: bool
      description:
        - Whether the `allowed_domains` list can use templates.
    allow_bare_domains:
      type: bool
      description:
        - Whether clients can request certificates matching the value of the actual domains themselves.
    allow_subdomains:
      type: bool
      description:
        - Whether clients can request certificates with CNs that are subdomains of the CNs allowed by
          the other role options. This includes wildcard subdomains.
    allow_glob_domains:
      type: bool
      description:
        - Allows names specified in `allowed_domains` to contain glob patterns (e.g. `ftp*.example.com`)
    allow_wildcard_certificates:
      type: bool
      description:
        - Whether clients can request wildcard certificates.
    allow_any_name:
      type: bool
      description:
        - Whether clients can request a certificate CN that is not in the `allowed_domains` list.
    enforce_hostnames:
      type: bool
      description:
        - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
          addresses.
    allow_ip_sans:
      type: bool
      description:
        - Whether clients can request IP Subject Alternative Names.
    allowed_uri_sans:
      type: list
      elements: str
      description:
        - The list of allowed URI Subject Alternative Names
    allowed_uri_sans_template:
      type: bool
      description:
        - Whether the `allowed_uri_sans` list can use templates.
    allowed_other_sans:
      type: list
      elements: str
      description:
        - Defines allowed custom OID/UTF8-string SANs
    server_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for server use.
    client_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for client use.
    code_signing_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for code signing use.
    email_protection_flag:
      type: bool
      description:
        - Whether certificates issued are flagged for email protection use.
    key_type:
      type: str
      description:
        - Specifies the type of key to generate for generated private keys and the type of key expected for
          submitted CSRs
    key_bits:
      type: int
      description:
        - Specifies the number of bits to use for the generated keys
    signature_bits:
      type: int
      description:
        - Specifies the number of bits to use for the generated signature.
    use_pss:
      type: bool
      description:
        - Whether to use the Probabilistic Signature Scheme (PSS) for RSA keys.
    key_usage:
      type: list
      elements: str
      description:
        - The list of allowed key usage constraints on issued certificates.
    ext_key_usage:
      type: list
      elements: str
      description:
        - The list of allowed extended key usage constraints on issued certificates.
    ext_key_usage_oids:
      type: list
      elements: str
      description:
        - A list of extended key usage oids.
    use_csr_common_name:
      type: bool
      description:
        - Whether the CSR common name is used, when signing a CSR.
    use_csr_sans:
      type: bool
      description:
        - Whether the CSR Subject Alternative Names (SANs) are used, when signing a CSR.
    ou:
      type: list
      elements: str
      description:
        - The list of OU (OrganizationalUnit) values in the subject field of issued certificates.
    organization:
      type: list
      elements: str
      description:
        - The list of O (Organization) values in the subject field of issued certificates.
    country:
      type: list
      elements: str
      description:
        - The list of C (Country) values in the subject field of issued certificates.
    locality:
      type: list
      elements: str
      description:
        - The list of L (Locality) values in the subject field of issued certificates.
    province:
      type: list
      elements: str
      description:
        - The list of ST (Province) values in the subject field of issued certificates.
    street_address:
      type: list
      elements: str
      description:
        - The list of Street Address values in the subject field of issued certificates.
    postal_code:
      type: list
      elements: str
      description:
        - The list of Postal Code values in the subject field of issued certificates.
    generate_lease:
      type: bool
      description:
        - Whether certificates issued/signed against this role will have Vault leases attached to them.
    no_store:
      type: bool
      description:
        - Whether certificates issued/signed against this role should be stored in the storage backend.
    require_cn:
      type: bool
      description:
        - If set to false, makes the `common_name` field optional while generating a certificate.
    policy_identifiers:
      type: list
      elements: str
      description:
          - A list of policy OIDs.
    basic_constraints_valid_for_non_ca:
      type: bool
      description:
        - Whether to mark Basic Constraints valid when issuing non-CA certificates.
    not_before_duration:
      type: str
      description:
        - The duration by which to backdate the NotBefore property.
    not_after:
      type: str
      description:
        - The value of the Not After field on issued certificates.
    allowed_user_ids:
      type: list
      elements: str
      description:
        - A list of allowed user IDs.
"""

import hvac
import traceback

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIRoleModule(VaultModule):
    """
    Vault PKI Role module.
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', default='present', choices=['present', 'absent']),
        ttl=dict(type='str', required=False),
        max_ttl=dict(type='str', required=False),
        allow_localhost=dict(type='bool', required=False),
        allowed_domains=dict(type='list', elements='str', required=False),
        allowed_domains_template=dict(type='bool', required=False),
        allow_bare_domains=dict(type='bool', required=False),
        allow_subdomains=dict(type='bool', required=False),
        allow_glob_domains=dict(type='bool', required=False),
        allow_wildcard_certificates=dict(type='bool', required=False),
        allow_any_name=dict(type='bool', required=False),
        enforce_hostnames=dict(type='bool', required=False),
        allow_ip_sans=dict(type='bool', required=False),
        allowed_uri_sans=dict(type='list', elements='str', required=False),
        allowed_uri_sans_template=dict(type='bool', required=False),
        allowed_other_sans=dict(type='list', elements='str', required=False),
        server_flag=dict(type='bool', required=False),
        client_flag=dict(type='bool', required=False),
        code_signing_flag=dict(type='bool', required=False),
        email_protection_flag=dict(type='bool', required=False),
        key_type=dict(type='str', required=False, choices=['rsa', 'ec']),
        key_bits=dict(type='int', required=False),
        signature_bits=dict(type='int', required=False),
        use_pss=dict(type='bool', required=False),
        key_usage=dict(
            type='list',
            elements='str',
            choices=[
                'DigitalSignature',
                'ContentCommitment',
                'KeyEncipherment',
                'DataEncipherment',
                'KeyAgreement',
                'CertSign',
                'CRLSign',
                'EncipherOnly',
                'DecipherOnly'
            ],
            required=False
        ),
        ext_key_usage=dict(
            type='list',
            elements='str',
            required=False,
            choices=[
                'ServerAuth',
                'ClientAuth',
                'CodeSigning',
                'EmailProtection',
                'IPSECEndSystem',
                'IPSECTunnel',
                'IPSECUser',
                'TimeStamping',
                'OCSPSigning',
                'MicrosoftServerGatedCrypto',
                'NetscapeServerGatedCrypto',
                'MicrosoftCommercialCodeSigning',
                'MicrosoftKernelCodeSigning'
            ]
        ),
        ext_key_usage_oids=dict(type='list', elements='str', required=False),
        use_csr_common_name=dict(type='bool', required=False),
        use_csr_sans=dict(type='bool', required=False),
        ou=dict(type='list', elements='str', required=False),
        organization=dict(type='list', elements='str', required=False),
        country=dict(type='list', elements='str', required=False),
        locality=dict(type='list', elements='str', required=False),
        province=dict(type='list', elements='str', required=False),
        street_address=dict(type='list', elements='str', required=False),
        postal_code=dict(type='list', elements='str', required=False),
        generate_lease=dict(type='bool', required=False),
        no_store=dict(type='bool', required=False),
        require_cn=dict(type='bool', required=False),
        policy_identifiers=dict(type='list', elements='str', required=False),
        basic_constraints_valid_for_non_ca=dict(type='bool', required=False),
        not_before_duration=dict(type='str', required=False),
        not_after=dict(type='str', required=False),
        allowed_user_ids=dict(type='list', elements='str', required=False)
    )

    DEFAULT_VALUES = dict(
        ttl=0,
        max_ttl=0,
        allow_localhost=True,
        allowed_domains=[],
        allowed_domains_template=False,
        allow_bare_domains=False,
        allow_subdomains=False,
        allow_glob_domains=False,
        allow_wildcard_certificates=True,
        allow_any_name=False,
        enforce_hostnames=True,
        allow_ip_sans=True,
        allowed_uri_sans=[],
        allowed_uri_sans_template=False,
        allowed_other_sans=[],
        server_flag=True,
        client_flag=True,
        code_signing_flag=False,
        email_protection_flag=False,
        key_type='rsa',
        key_bits=2048,
        signature_bits=256,
        use_pss=False,
        key_usage=['DigitalSignature', 'KeyAgreement', 'KeyEncipherment'],
        ext_key_usage=[],
        ext_key_usage_oids=[],
        use_csr_common_name=True,
        use_csr_sans=True,
        ou=[],
        organization=[],
        country=[],
        locality=[],
        province=[],
        street_address=[],
        postal_code=[],
        generate_lease=False,
        no_store=False,
        require_cn=True,
        policy_identifiers=[],
        basic_constraints_valid_for_non_ca=False,
        not_before_duration=30,
        not_after='',
        allowed_user_ids=[]
    )

    SET_COMPARE_PARAMS = [
        'allowed_domains',
        'allowed_uri_sans',
        'allowed_other_sans',
        'key_usage',
        'ext_key_usage',
        'ext_key_usage_oids',
        'policy_identifiers'
    ]

    DURATION_PARAMS = ['ttl', 'max_ttl', 'not_before_duration']

    def __init__(self, *args, **kwargs):
        
        argspec = self.ARGSPEC.copy()

        super(VaultPKIRoleModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            **kwargs)
    

    def get_defined_role_params(self) -> dict:
        """
        Get the defined role parameters.

        Returns:
            dict: The defined role parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys = [key for key in filtered_params.keys() if key not in self.DEFAULT_VALUES.keys()]

        for key in delete_keys:
            del filtered_params[key]
        
        delete_keys = [key for key in filtered_params.keys() if filtered_params[key] is None]

        for key in delete_keys:
            del filtered_params[key]
        
        for key, value in filtered_params.items():
            if key in self.DURATION_PARAMS:
                filtered_params[key] = duration_str_to_seconds(value)
            
        return filtered_params


    def format_role_data(self, config_data: dict) -> dict:
        """
        Format the data for a PKI role.

        Args:
            config_data (dict): The data to format.
        
        Returns:
            dict: The formatted data.
        """

        formatted_config_data: dict = {}

        for key, value in config_data.items():
            if key in self.DEFAULT_VALUES:
                formatted_config_data[key] = value

        return formatted_config_data


    def get_formatted_role_data(self) -> dict | None:
        """
        Get the formatted data for a PKI role.

        Args:
            client (Client): The Vault client to use.
            mount_point (str): The mount point of the PKI engine.
            name (str): The name of the role to get the data for.

        Returns:
            dict: The formatted data for the PKI role.
        """

        name: str = self.params['name']
        mount_point: str = self.params['engine_mount_point']

        try:
            config: dict = self.client.secrets.pki.read_role(name, mount_point=mount_point)
        except hvac.exceptions.InvalidPath:
            return None
        except hvac.exceptions.UnexpectedError:
            return None
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission denied to read PKI role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error reading PKI role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        
        formatted_config: dict = self.format_role_data(config.get('data', dict()))

        return formatted_config


    def compare_role(self, previous_config: dict, desired_config: dict) -> dict:
        """
        Compare the PKI roles.

        Args:
            previous (dict): The previous PKI role.
            desired (dict): The desired PKI role.

        Returns:
            dict: The differences between the two PKI roles.
        """

        config_diff: dict = {}

        for key, value in desired_config.items():
            if key not in previous_config:
                if key in self.SET_COMPARE_PARAMS:
                    if set(value) != set(self.DEFAULT_VALUES[key]):
                        config_diff[key] = value
                else:
                    if value != self.DEFAULT_VALUES[key]:
                        config_diff[key] = value
            else:
                if key in self.SET_COMPARE_PARAMS:
                    if set(value) != set(previous_config[key]):
                        config_diff[key] = value
                else:
                    if value != previous_config[key]:
                        config_diff[key] = value
        
        if 'cn_validations' in config_diff and config_diff['cn_validations'] == []:
            config_diff['cn_validations'] = ''
        
        return config_diff


def ensure_role_absent(module: VaultPKIRoleModule, previous_role_data: dict | None) -> dict:
    """
    Ensure that a PKI role is absent.

    Args:
        module (VaultPKIRoleModule): The module object.
        previous_role_data (dict): The previous role data.

    Returns:
        dict: The result of the operation.
    """

    if previous_role_data is None:
        return dict(changed=False)

    name = module.params['name']
    mount_point = module.params['engine_mount_point']

    if not module.check_mode:
        try:
            module.client.secrets.pki.delete_role(name, mount_point=mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error deleting PKI role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
    
    return dict(changed=True, prev_role=previous_role_data)


def ensure_role_present(
        module: VaultPKIRoleModule,
        previous_role_data: dict | None,
        desired_role_data: dict) -> dict:
    """
    Ensure that a PKI role is present.

    Args:
        module (VaultPKIRoleModule): The module object.
        previous_role_data (dict): The previous role data.
        desired_role_data (dict): The desired role data.

    Returns:
        dict: The result of the operation.
    """

    name = module.params['name']
    mount_point = module.params['engine_mount_point']
    
    if previous_role_data is None:
        
        if not module.check_mode:
            try:
                module.client.secrets.pki.create_or_update_role(
                    name,
                    mount_point=mount_point,
                    extra_params=desired_role_data
                )
            except Exception:
                module.handle_error(
                    VaultModuleError(
                        message=f"Error creating PKI role '{name}' at mount point '{mount_point}'",
                        exception=traceback.format_exc()
                    )
                )

        return dict(changed=True, role=desired_role_data)
    
    config_diff = module.compare_role(
        previous_role_data,
        desired_role_data
    )

    if not config_diff:
        return dict(changed=False, role=desired_role_data)
    
    if not module.check_mode:
        try:
            module.client.secrets.pki.create_or_update_role(
                name,
                mount_point=mount_point,
                extra_params=config_diff
            )
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error updating PKI role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_role=previous_role_data, role=desired_role_data)


def run_module():

    module = VaultPKIRoleModule()

    state: bool = module.params['state']

    desired_role_data = module.get_defined_role_params()

    module.initialize_client()

    previous_role_data = module.get_formatted_role_data()
    
    if state == 'present':
        result = ensure_role_present(
            module,
            previous_role_data,
            desired_role_data
        )
    else:
        result = ensure_role_absent(
            module,
            previous_role_data
        )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
