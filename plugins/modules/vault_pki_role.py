#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_role
version_added: 1.2.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures a PKI secret engine role in HashiCorp Vault
description:
  - >-
    Ensures a L(PKI secret engine role,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html#create-update-role)
    is configured as expected in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
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
      - The default expiration period for issued certificates from this role.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - >-
        If not provided, this defaults to the shorter of the secret engine V(default_lease_ttl) value
        and the O(max_ttl) value on new roles.
  max_ttl:
    type: str
    required: false
    description:
      - The maximum expiration period for issued certificates from this role.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If not provided, this defaults to the secret engine V(max_lease_ttl) value on new roles.
  allow_localhost:
    type: bool
    required: false
    description:
      - Whether clients can request certificates for V(localhost) as one of the requested common names.
      - If not provided, this defaults to V(true) on new roles.
  allowed_domains:
    type: list
    required: false
    elements: str
    description:
      - The domains for which this role can issue certificates.
      - Only used when O(allow_bare_domains=true) or O(allow_subdomains=true).
      - If not provided, this defaults to an empty list on new roles.
  allowed_domains_template:
    type: bool
    required: false
    description:
      - Whether the O(allowed_domains) list can include templates.
      - If not provided, this defaults to V(false) on new roles.
  allow_bare_domains:
    type: bool
    required: false
    description:
      - Whether clients can request certificates matching the value of the actual domains themselves.
      - >-
        For example, if O(allowed_domains) includes V(example.com) and O(allow_bare_domains=true),
        the name V(example.com) is an allowed name.
      - In some scenarios, this can be considered a security risk.
      - If not provided, this defaults to V(false) on new roles.
  allow_subdomains:
    type: bool
    required: false
    description:
      - >-
        Whether clients can request certificates with CNs that are subdomains of the CNs allowed by
        the other role options. This includes wildcard subdomains.
      - >-
        For example, if O(allowed_domains) includes V(example.com) and O(allow_subdomains=true),
        V(foo.example.com), V(bar.example.com), and V(*.example.com) are allowed names.
      - Redundant when O(allow_any_name=true).
      - If not provided, this defaults to V(false) on new roles.
  allow_glob_domains:
    type: bool
    required: false
    description:
      - Allows names specified in O(allowed_domains) to contain glob patterns (e.g. V(ftp*.example.com))
      - Clients will be allowed to request certificates with names matching the glob patterns.
      - If not provided, this defaults to V(false) on new roles.
  allow_wildcard_certificates:
    type: bool
    required: false
    description:
      - Whether clients can request wildcard certificates.
      - If not provided, this defaults to V(true) on new roles.
  allow_any_name:
    type: bool
    required: false
    description:
      - Whether clients can request a certificate CN that is not in the O(allowed_domains) list.
      - If not provided, this defaults to V(false) on new roles.
  enforce_hostnames:
    type: bool
    required: false
    description:
      - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
        addresses.
      - If not provided, this defaults to V(true) on new roles.
  allow_ip_sans:
    type: bool
    required: false
    description:
      - Whether clients can request IP Subject Alternative Names (SANs).
      - No authorization checking is performed except to verify that the given values are valid IP addresses.
      - If not provided, this defaults to V(true) on new roles.
  allowed_uri_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of allowed URI Subject Alternative Names (SANs).
      - No authorization checking is performed except to verify that the given values are valid URIs.
      - Values can contain glob patterns (e.g. V(spiffe://hostname/*)).
      - If not provided, this defaults to an empty list on new roles.
  allowed_uri_sans_template:
    type: bool
    required: false
    description:
      - Whether the O(allowed_uri_sans) list can use templates.
      - If not provided, this defaults to V(false) on new roles.
  allowed_other_sans:
    type: list
    required: false
    elements: str
    description:
      - Defines allowed custom OID/UTF8-string SANs
      - >-
        This can be a comma-delimited list or a JSON string slice, where each element has the same format
        as OpenSSL V(<oid>;<type>:<value>), but the only valid type is V(UTF8) or V(UTF-8).
      - The V(value) part of an element may be a V(*) to allow any value with that OID.
      - Alternatively, specifying a single V(*) will allow any other_sans input.
      - If not provided, this defaults to an empty list on new roles.
  server_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for server use.
      - If not provided, this defaults to V(true) on new roles.
  client_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for client use.
      - If not provided, this defaults to V(true) on new roles.
  code_signing_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for code signing use.
      - If not provided, this defaults to V(false) on new roles.
  email_protection_flag:
    type: bool
    required: false
    description:
      - Whether certificates issued are flagged for email protection use.
      - If not provided, this defaults to V(false) on new roles.
  key_type:
    type: str
    required: false
    choices:
      - rsa
      - ec
      - any
    description:
      - >-
        The type of key to generate for generated private keys and the type of key expected for
        submitted certificate signing requests (CSRs).
      - >-
        Currently, V(rsa) and V(ec) are supported, or when signing CSRs V(any) can be specified to
        allow keys of either type and with any bit size (subject to > 1024 bits for RSA keys).
      - If not provided, this defaults to V(rsa) on new roles.
  key_bits:
    type: int
    required: false
    choices:
      - 224
      - 256
      - 384
      - 521
      - 2048
      - 3072
      - 4096
      - 8192
    description:
      - The number of bits to use for generated keys.
      - If O(key_type=rsa), the allowed values are V(2048), V(3072), V(4096), and V(8192).
      - If not provided and O(key_type=rsa), this defaults to V(2048) on new roles.
      - If O(key_type=ec), the allowed values are V(224), V(256), V(384), and V(521).
      - If not provided and O(key_type=ec), this defaults to V(256) on new roles.
      - If O(key_type=any), this should not be provided.
  signature_bits:
    type: int
    required: false
    choices:
      - 256
      - 384
      - 512
    description:
      - The signature algorithm bit length for the signed certificates.
      - Should only be provided when O(key_type=rsa).
      - If not provided, this defaults to V(256) on new roles.
  use_pss:
    type: bool
    required: false
    description:
      - Whether to use the Probabilistic Signature Scheme (PSS) for RSA keys.
      - Should only be provided when O(key_type=rsa).
      - If not provided, this defaults to V(false) on new roles.
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
      - To specify no key usage constraints, the value must be set to an empty list.
      - If not provided, this defaults to V(DigitalSignature), V(KeyAgreement), and V(KeyEncipherment) on new roles.
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
      - To specify no extended key usage constraints, set this to an empty list.
      - If not provided, this defaults to an empty list on new roles.
  ext_key_usage_oids:
    type: list
    required: false
    elements: str
    description:
      - The list of extended key usage oids.
      - If not provided, this defaults to an empty list on new roles.
  use_csr_common_name:
    type: bool
    required: false
    description:
      - Whether the CSR common name is used, when signing a CSR.
      - This has no effect when generating a certificate without a CSR.
      - If not provided, this defaults to V(true) on new roles.
  use_csr_sans:
    type: bool
    required: false
    description:
      - Whether the CSR Subject Alternative Names (SANs) are used, when signing a CSR.
      - This has no effect when generating a certificate without a CSR.
      - If not provided, this defaults to V(true) on new roles.
  ou:
    type: list
    required: false
    elements: str
    description:
      - The Organizational Unit (OU) values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  organization:
    type: list
    required: false
    elements: str
    description:
      - The Organization (O) values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  country:
    type: list
    required: false
    elements: str
    description:
      - The Country (C) values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  locality:
    type: list
    required: false
    elements: str
    description:
      - The Locality (L) values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  province:
    type: list
    required: false
    elements: str
    description:
      - The Province or State (ST) values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  street_address:
    type: list
    required: false
    elements: str
    description:
      - The Street Address values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  postal_code:
    type: list
    required: false
    elements: str
    description:
      - The Postal Code values to include in issued/signed certificates.
      - If not provided, this defaults to an empty list on new roles.
  generate_lease:
    type: bool
    required: false
    description:
      - Whether certificates issued/signed against this role will have Vault leases attached to them.
      - >-
        A lease is required to revoke a certificate and add it to the Certificate Revocation List
        (CRL) from the command line or GUI.
      - A lease is not required to revoke a certificate using the C(pki/revoke) API endpoint.
      - If not provided, this defaults to V(false) on new roles.
  no_store:
    type: bool
    required: false
    description:
      - Whether certificates issued/signed against this role should be stored in the storage backend.
      - This can improve performance when issuing large numbers of certificates.
      - >-
        However, certificates issued in this way cannot be enumerated or revoked, so this option is
        recommended only for certificates that are non-sensitive, or extremely short-lived.
      - If this is set to V(false), O(generate_lease=true) will not be effective.
      - If not provided, this defaults to V(false) on new roles.
  require_cn:
    type: bool
    required: false
    description:
      - Whether certificate signing requests (CSRs) must include a common name (CN).
      - If not provided, this defaults to V(true) on new roles.
  policy_identifiers:
    type: list
    required: false
    elements: str
    description:
      - The list of policy OIDs.
      - If not provided, this defaults to an empty list on new roles.
  basic_constraints_valid_for_non_ca:
    type: bool
    required: false
    description:
      - Whether to mark Basic Constraints valid when issuing non-CA certificates.
      - If not provided, this defaults to V(false) on new roles.
  not_before_duration:
    type: str
    required: false
    description:
      - The duration by which to backdate the NotBefore property.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If not provided, this defaults to V(30s) on new roles.
  not_after:
    type: str
    required: false
    description:
      - The latest value of the NotAfter field on issued certificates.
      - This must be in UTC C(YYYY-MM-ddTHH:MM:SSZ) format.
      - If set to an empty string, no limit will be set on issued certificates.
      - If not provided, this defaults to an empty string on new roles.
  allowed_user_ids:
    type: list
    required: false
    elements: str
    description:
      - The list of allowed user IDs.
      - If not provided, this defaults to an empty list on new roles.
"""

EXAMPLES = r"""
- name: Creates a PKI role
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
  returned: O(state=present)
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
        - The default expiration period for issued certificates from this role.
    max_ttl:
      type: str
      description:
      - The maximum expiration period for issued certificates from this role.
    allow_localhost:
      type: bool
      description:
      - Whether clients can request certificates for V(localhost) as one of the requested common names.
    allowed_domains:
      type: list
      elements: str
      description:
        - The domains for which this role can issue certificates.
    allowed_domains_template:
      type: bool
      description:
        - Whether the O(allowed_domains) list can include templates.
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
        - Allows names specified in O(allowed_domains) to contain glob patterns (e.g. V(ftp*.example.com))
    allow_wildcard_certificates:
      type: bool
      description:
        - Whether clients can request wildcard certificates.
    allow_any_name:
      type: bool
      description:
        - Whether clients can request a certificate CN that is not in the O(allowed_domains) list.
    enforce_hostnames:
      type: bool
      description:
        - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
          addresses.
    allow_ip_sans:
      type: bool
      description:
        - Whether clients can request IP Subject Alternative Names (SANs).
    allowed_uri_sans:
      type: list
      elements: str
      description:
        - The list of allowed URI Subject Alternative Names (SANs).
    allowed_uri_sans_template:
      type: bool
      description:
        - Whether the O(allowed_uri_sans) list can use templates.
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
        - The type of key to generate for generated private keys and the type of key expected for
          submitted CSRs.
    key_bits:
      type: int
      description:
        - The number of bits to use for generated keys.
    signature_bits:
      type: int
      description:
        - The signature algorithm bit length for the signed certificates.
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
        - The list of extended key usage oids.
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
        - The Organizational Unit (OU) values to include in issued/signed certificates.
    organization:
      type: list
      elements: str
      description:
        - The Organization (O) values to include in issued/signed certificates.
    country:
      type: list
      elements: str
      description:
        - The Country (C) values to include in issued/signed certificates.
    locality:
      type: list
      elements: str
      description:
        - The Locality (L) values to include in issued/signed certificates.
    province:
      type: list
      elements: str
      description:
        - The Province or State (ST) values to include in issued/signed certificates.
    street_address:
      type: list
      elements: str
      description:
        - The Street Address values to include in issued/signed certificates.
    postal_code:
      type: list
      elements: str
      description:
        - The Postal Code values to include in issued/signed certificates.
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
        - Whether certificate signing requests (CSRs) must include a common name (CN).
    policy_identifiers:
      type: list
      elements: str
      description:
        - The list of policy OIDs.
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
        - This must be in UTC C(YYYY-MM-ddTHH:MM:SSZ) format.
    allowed_user_ids:
      type: list
      elements: str
      description:
        - The list of allowed user IDs.
prev_config:
  type: dict
  returned: changed
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
        - The default expiration period for issued certificates from this role.
    max_ttl:
      type: str
      description:
      - The maximum expiration period for issued certificates from this role.
    allow_localhost:
      type: bool
      description:
      - Whether clients can request certificates for V(localhost) as one of the requested common names.
    allowed_domains:
      type: list
      elements: str
      description:
        - The domains for which this role can issue certificates.
    allowed_domains_template:
      type: bool
      description:
        - Whether the O(allowed_domains) list can include templates.
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
        - Allows names specified in O(allowed_domains) to contain glob patterns (e.g. V(ftp*.example.com))
    allow_wildcard_certificates:
      type: bool
      description:
        - Whether clients can request wildcard certificates.
    allow_any_name:
      type: bool
      description:
        - Whether clients can request a certificate CN that is not in the O(allowed_domains) list.
    enforce_hostnames:
      type: bool
      description:
        - Whether only valid host names are allowed for CNs, DNS SANs, and the host part of email
          addresses.
    allow_ip_sans:
      type: bool
      description:
        - Whether clients can request IP Subject Alternative Names (SANs).
    allowed_uri_sans:
      type: list
      elements: str
      description:
        - The list of allowed URI Subject Alternative Names (SANs).
    allowed_uri_sans_template:
      type: bool
      description:
        - Whether the O(allowed_uri_sans) list can use templates.
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
        - The type of key to generate for generated private keys and the type of key expected for
          submitted CSRs.
    key_bits:
      type: int
      description:
        - The number of bits to use for generated keys.
    signature_bits:
      type: int
      description:
        - The signature algorithm bit length for the signed certificates.
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
        - The list of extended key usage oids.
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
        - The Organizational Unit (OU) values to include in issued/signed certificates.
    organization:
      type: list
      elements: str
      description:
        - The Organization (O) values to include in issued/signed certificates.
    country:
      type: list
      elements: str
      description:
        - The Country (C) values to include in issued/signed certificates.
    locality:
      type: list
      elements: str
      description:
        - The Locality (L) values to include in issued/signed certificates.
    province:
      type: list
      elements: str
      description:
        - The Province or State (ST) values to include in issued/signed certificates.
    street_address:
      type: list
      elements: str
      description:
        - The Street Address values to include in issued/signed certificates.
    postal_code:
      type: list
      elements: str
      description:
        - The Postal Code values to include in issued/signed certificates.
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
        - Whether certificate signing requests (CSRs) must include a common name (CN).
    policy_identifiers:
      type: list
      elements: str
      description:
        - The list of policy OIDs.
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
        - This must be in UTC C(YYYY-MM-ddTHH:MM:SSZ) format.
    allowed_user_ids:
      type: list
      elements: str
      description:
        - The list of allowed user IDs.
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import List, Optional

try:
    import hvac
    import hvac.exceptions
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIRoleModule(VaultModule):
    """
    Vault PKI Role module.
    """

    ARGSPEC: dict = dict(
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
        key_type=dict(type='str', required=False, choices=['rsa', 'ec', 'any']),
        key_bits=dict(
            type='int',
            required=False,
            choices=[
                224,
                256,
                384,
                521,
                2048,
                3072,
                4096,
                8192
            ]
        ),
        signature_bits=dict(type='int', required=False, choices=[256, 384, 512]),
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

    DEFAULT_VALUES: dict = dict(
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

    SET_COMPARE_PARAMS: List[str] = [
        'allowed_domains',
        'allowed_uri_sans',
        'allowed_other_sans',
        'key_usage',
        'ext_key_usage',
        'ext_key_usage_oids',
        'policy_identifiers'
    ]

    DURATION_PARAMS: List[str] = ['ttl', 'max_ttl', 'not_before_duration']

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

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

        delete_keys: List[str] = [key for key in filtered_params.keys() if key not in self.DEFAULT_VALUES.keys()]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys: List[str] = [key for key in filtered_params.keys() if filtered_params[key] is None]

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

    def get_formatted_role_data(self) -> Optional[dict]:
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


def ensure_role_absent(module: VaultPKIRoleModule, previous_role_data: Optional[dict]) -> dict:
    """
    Ensure that a PKI role is absent.

    Args:
        module (VaultPKIRoleModule): The module object.
        previous_role_data (Optional[dict]): The previous role data.

    Returns:
        dict: The result of the operation.
    """

    if previous_role_data is None:
        return dict(changed=False)

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']

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
        previous_role_data: Optional[dict],
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

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']

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

    config_diff: dict = module.compare_role(
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


def run_module() -> None:

    module: VaultPKIRoleModule = VaultPKIRoleModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params['state']

    desired_role_data: dict = module.get_defined_role_params()

    module.initialize_client()

    previous_role_data: Optional[dict] = module.get_formatted_role_data()

    if state == 'present':
        result: dict = ensure_role_present(
            module,
            previous_role_data,
            desired_role_data
        )
    else:
        result: dict = ensure_role_absent(
            module,
            previous_role_data
        )

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
