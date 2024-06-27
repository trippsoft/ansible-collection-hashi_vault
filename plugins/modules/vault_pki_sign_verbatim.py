#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_sign_verbatim
version_added: 1.2.0
author:
  - Jim Tarpley
short_description: Signs a certificate signing request (CSR) verbatim in HashiCorp Vault.
requirements:
  - C(hvac) (L(Python library,https://hvac.readthedocs.io/en/stable/overview.html))
  - For detailed requirements, see R(the collection requirements page,ansible_collections.community.hashi_vault.docsite.user_guide.requirements).
description:
  - Signs a certificate signing request (CSR) verbatim in HashiCorp Vault.
  - This module is not idempotent.
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
  role_name:
    type: str
    required: true
    description:
      - The name of the role to use for signing the CSR.
  csr:
    type: str
    required: true
    description:
      - The certificate signing request (CSR) to sign.
  key_usage:
    type: list
    required: false
    default:
      - DigitalSignature
      - KeyEncipherment
      - KeyAgreement
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
  ext_key_usage:
    type: list
    required: false
    default: []
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
  enforce_leaf_not_after_behavior:
    type: bool
    required: false
    default: false
    description:
      - Whether to enforce the leaf certificate not after behavior.
  ttl:
    type: str
    required: false
    description:
      - The time-to-live (TTL) of the signed certificate.
      - This value can be supplied as a string with a time unit suffix (e.g., '1h', '2h', '1h30m') or as a number of seconds.
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
      - The not after time of the signed certificate.
      - This value is a UTC timestamp in YYYY-MM-ddTHH:MM:SSZ format.
  signature_bits:
    type: int
    required: false
    description:
      - The number of bits in the signature.
      - This defaults to the appropriate value for the key type.
  uss_pss:
    type: bool
    required: false
    default: false
    description:
      - Whether to use the RSASSA-PSS signature algorithm.
  remove_roots_from_chain:
    type: bool
    required: false
    default: false
    description:
      - Whether to remove the root certificates from the chain.
  user_ids:
    type: list
    required: false
    default: []
    elements: str
    description:
      - A list of user IDs to include in the signed certificate.
"""

EXAMPLES = r"""
- name: Sign a certificate signing request (CSR) verbatim
  trippsc2.hashi_vault.vault_pki_sign_verbatim:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    role_name: my-role
    csr: '{{ lookup("file", "csr.pem") }}'
"""

RETURN = r"""
certificate:
  type: str
  description:
    - The signed certificate.
issuing_ca:
  type: str
  description:
    - The issuing certificate authority (CA).
ca_chain:
  type: list
  elements: str
  description:
    - The certificate chain.
serial_number:
  type: str
  description:
    - The serial number of the signed certificate.
"""

import traceback

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKISignVerbatimModule(VaultModule):
    """
    Vault PKI sign verbatim module.
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        role_name=dict(type='str', required=True),
        csr=dict(type='str', required=True),
        key_usage=dict(type='list', required=False, elements='str'),
        ext_key_usage=dict(type='list', required=False, elements='str'),
        enforce_leaf_not_after_behavior=dict(type='bool', required=False),
        ttl=dict(type='str', required=False),
        format=dict(type='str', required=False, default='pem', choices=['pem', 'der', 'pem_bundle']),
        not_after=dict(type='str', required=False),
        signature_bits=dict(type='int', required=False),
        uss_pss=dict(type='bool', required=False),
        remove_roots_from_chain=dict(type='bool', required=False),
        user_ids=dict(type='list', required=False, elements='str')
    )

    DURATION_ARGS = ['ttl']


    def __init__(self, *args, **kwargs):

        argspec = self.ARGSPEC.copy()

        super(VaultPKISignVerbatimModule, self).__init__(
            *args,
            argument_spec=argspec,
            **kwargs
        )


    def get_defined_extra_params(self) -> dict | None:
        """
        Get the defined extra parameters.

        Returns:
            dict: The defined extra parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys = [key for key in filtered_params.keys() if key not in self.ARGSPEC]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys = [key for key in filtered_params.keys() if key in ['engine_mount_point', 'role_name', 'csr']]

        for key in delete_keys:
            del filtered_params[key]
        
        delete_keys = [key for key in filtered_params.keys() if filtered_params[key] is None]

        for key in delete_keys:
            del filtered_params[key]
        
        for key in self.DURATION_ARGS:
            if key in filtered_params:
                filtered_params[key] = duration_str_to_seconds(filtered_params[key])

        if len(filtered_params) == 0:
            return None

        return filtered_params


def run_module():
    
    module = VaultPKISignVerbatimModule()
    module.initialize_client()

    engine_mount_point: str = module.params['engine_mount_point']
    role_name: str = module.params['role_name']
    csr: str = module.params['csr']

    extra_params: dict | None = module.get_defined_extra_params()

    try:
        response = module.client.secrets.pki.sign_verbatim(
            csr=csr,
            name=role_name,
            extra_params=extra_params,
            mount_point=engine_mount_point
        )
    except Exception:
        module.handle_error(
            VaultModuleError(
                message="An error occurred signing the certificate verbatim",
                exception=traceback.format_exc()
            )
        )
        
    module.exit_json(changed=True, **response["data"])


def main():
    run_module()


if __name__ == '__main__':
    main()
