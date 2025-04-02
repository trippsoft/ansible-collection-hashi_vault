#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_sign_intermediate
version_added: 1.8.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Signs a certificate signing request as an intermediate CA in HashiCorp Vault
description:
  - >-
    L(Signs a certificate signing request \(CSR\) as an intermediate CA,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html#sign-intermediate)
    in HashiCorp Vault.
  - This module is not idempotent.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode_none
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
options:
  csr:
    type: str
    required: true
    description:
      - The certificate signing request (CSR) to sign.
  common_name:
    type: str
    required: true
    description:
      - The requested common name (CN) attribute for the intermediate CA.
  alt_names:
    type: list
    required: false
    elements: str
    description:
      - The list of Subject Alternative Names (SANs) to include in the intermediate CA.
      - Each element should be a hostname (DNS name) or an email address.
      - >-
        If this does not include the common name and O(exclude_cn_from_sans=false), the common name will be
        added to the list of SANs.
      - If not provided, an empty list will be used.
  ip_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of IP Subject Alternative Names (IP SANs) to include in the intermediate CA.
      - Each element should be a valid IP address.
      - If not provided, an empty list will be used.
  uri_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of URI Subject Alternative Names (URI SANs) to include in the intermediate CA.
      - Each element should be a valid URI.
      - If not provided, an empty list will be used.
  other_sans:
    type: list
    required: false
    elements: dict
    description:
      - The list of custom OID/UTF8-string SANs.
      - If not provided, an empty list will be used.
    suboptions:
      oid:
        type: str
        required: true
        description:
          - The OID for the custom SAN.
      type:
        type: str
        required: false
        default: utf8
        choices:
          - utf8
        description:
          - The type of the custom SAN.
      value:
        type: str
        required: true
        description:
          - The value of the custom SAN.
  exclude_cn_from_sans:
    type: bool
    required: false
    description:
      - Whether to exclude the common name from the Subject Alternate Names (SANs).
      - If set to V(true), the given O(common_name) will not be added to the list of SANs.
      - >-
        If set to V(false), the given O(common_name) will be added to the list of SANs and parsed
        as a DNS name or email address.
      - If not provided, the common name will not be excluded.
  ou:
    type: list
    required: false
    elements: str
    description:
      - The Organizational Unit (OU) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  organization:
    type: list
    required: false
    elements: str
    description:
      - The Organization (O) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  country:
    type: list
    required: false
    elements: str
    description:
      - The Country (C) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  locality:
    type: list
    required: false
    elements: str
    description:
      - The Locality (L) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  province:
    type: list
    required: false
    elements: str
    description:
      - The Province or State (ST) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  street_address:
    type: list
    required: false
    elements: str
    description:
      - The Street Address values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  postal_code:
    type: list
    required: false
    elements: str
    description:
      - The Postal Code values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  serial_number:
    type: str
    required: false
    description:
      - The serial number of the CA certificate.
      - If you want more than one, specify alternative names in the alt_names map using OID 2.5.4.5.
      - If not provided, HashiCorp Vault will generate a random serial number for the certificate.
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
      - The key usage of the signed certificate.
      - If not provided, Vault defaults to providing V(DigitalSignature), V(KeyEncipherment), and V(KeyAgreement) key usages.
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
      - The extended key usage of the signed certificate.
      - If not provided, no extended key usage will be included.
  ttl:
    type: str
    required: false
    description:
      - The expiration duration of the signed certificate.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If not provided, this defaults to the C(default_lease_ttl) value of the role.
  format:
    type: str
    required: false
    default: pem
    choices:
      - pem
      - der
      - pem_bundle
    description:
      - The format of the signed certificate.
  not_after:
    type: str
    required: false
    description:
      - The latest date and time at which the signed certificate is valid.
      - This value is a UTC timestamp in C(YYYY-MM-ddTHH:MM:SSZ) format.
      - If not provided, this defaults to the C(not_after) value on the role.
  signature_bits:
    type: int
    required: false
    choices:
      - 256
      - 384
      - 512
    description:
      - The signature algorithm bit length for the signed certificates.
      - Should only be provided when CSR has a private key using the RSA algorithm.
      - If not provided, this defaults to the C(signature_bits) on the role.
  uss_pss:
    type: bool
    required: false
    description:
      - Whether to use the Probabilistic Signature Scheme (PSS) for RSA keys.
      - Should only be provided when CSR has a private key using the RSA algorithm.
      - If not provided, this defaults to the C(use_pss) on the role.
"""

EXAMPLES = r"""
- name: Sign a certificate signing request (CSR) as an intermediate CA
  trippsc2.hashi_vault.vault_pki_sign_intermediate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    csr: '{{ lookup("file", "csr.pem") }}'
    common_name: Intermediate CA
"""

RETURN = r"""
certificate:
  type: str
  returned: success
  description:
    - The signed certificate.
issuing_ca:
  type: str
  returned: success
  description:
    - The issuing certificate authority (CA).
ca_chain:
  type: list
  elements: str
  returned: success
  description:
    - The certificate chain.
serial_number:
  type: str
  returned: success
  description:
    - The serial number of the signed certificate.
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import List, Optional

try:
    import hvac
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_cert import other_sans_to_list_of_str
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKISignIntermediateModule(VaultModule):
    """
    Vault PKI sign verbatim module.
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        csr=dict(type='str', required=True),
        common_name=dict(type='str', required=True),
        alt_names=dict(type='list', required=False, elements='str'),
        ip_sans=dict(type='list', required=False, elements='str'),
        uri_sans=dict(type='list', required=False, elements='str'),
        other_sans=dict(
            type='list',
            required=False,
            elements='dict',
            options=dict(
                oid=dict(type='str', required=True),
                type=dict(type='str', required=False, default='utf8', choices=['utf8']),
                value=dict(type='str', required=True)
            )
        ),
        exclude_cn_from_sans=dict(type='bool', required=False),
        ou=dict(type='list', required=False, elements='str'),
        organization=dict(type='list', required=False, elements='str'),
        country=dict(type='list', required=False, elements='str'),
        locality=dict(type='list', required=False, elements='str'),
        province=dict(type='list', required=False, elements='str'),
        street_address=dict(type='list', required=False, elements='str'),
        postal_code=dict(type='list', required=False, elements='str'),
        serial_number=dict(type='str', required=False),
        key_usage=dict(
            type='list',
            required=False,
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
            ]),
        ext_key_usage=dict(
            type='list',
            required=False,
            elements='str',
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
            ]),
        ttl=dict(type='str', required=False),
        format=dict(type='str', required=False, default='pem', choices=['pem', 'der', 'pem_bundle']),
        not_after=dict(type='str', required=False),
        signature_bits=dict(type='int', required=False, choices=[256, 384, 512]),
        uss_pss=dict(type='bool', required=False)
    )

    DURATION_ARGS: List[str] = ['ttl']
    LIST_PARAMS_TO_JOIN: List[str] = ['alt_names']

    def __init__(self, *args, **kwargs):

        argspec: dict = self.ARGSPEC.copy()

        super(VaultPKISignIntermediateModule, self).__init__(
            *args,
            argument_spec=argspec,
            **kwargs
        )

    def get_defined_extra_params(self) -> Optional[dict]:
        """
        Get the defined extra parameters.

        Returns:
            dict: The defined extra parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys: List[str] = [key for key in filtered_params.keys() if key not in self.ARGSPEC]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys: List[str] = [key for key in filtered_params.keys() if key in ['engine_mount_point', 'csr', 'common_name']]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys: List[str] = [key for key in filtered_params.keys() if filtered_params[key] is None]

        for key in delete_keys:
            del filtered_params[key]

        for key in self.DURATION_ARGS:
            if key in filtered_params:
                filtered_params[key] = duration_str_to_seconds(filtered_params[key])

        for key, value in filtered_params.items():
            if key == 'other_sans':
                filtered_params[key] = other_sans_to_list_of_str(value)
                continue

            if key in self.LIST_PARAMS_TO_JOIN:
                filtered_params[key] = self.convert_list_to_comma_separated_string(value)
                continue

        if len(filtered_params) == 0:
            return None

        return filtered_params


def run_module() -> None:

    module: VaultPKISignIntermediateModule = VaultPKISignIntermediateModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    engine_mount_point: str = module.params['engine_mount_point']
    csr: str = module.params['csr']
    common_name: str = module.params['common_name']

    extra_params: Optional[dict] = module.get_defined_extra_params()

    try:
        response: dict = module.client.secrets.pki.sign_intermediate(
            csr=csr,
            common_name=common_name,
            extra_params=extra_params,
            mount_point=engine_mount_point
        )
    except Exception:
        module.handle_error(
            VaultModuleError(
                message="An error occurred signing the certificate as intermediate CA.",
                exception=traceback.format_exc()
            )
        )

    module.exit_json(changed=True, **response["data"])


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
