#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_sign_verbatim
version_added: 1.2.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Signs a certificate signing request verbatim in HashiCorp Vault
description:
  - >-
    L(Signs a certificate signing request \(CSR\) verbatim,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html#sign-verbatim)
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
  role_name:
    type: str
    required: true
    description:
      - The name of the role to use when signing the certificate signing request (CSR).
  csr:
    type: str
    required: true
    description:
      - The certificate signing request (CSR) to sign.
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
  enforce_leaf_not_after_behavior:
    type: bool
    required: false
    description:
      - Whether to enforce the leaf certificate NotAfter field behavior.
      - If not provided, this defaults to not enforcing the leaf certificate NotAfter field behavior.
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
  remove_roots_from_chain:
    type: bool
    required: false
    description:
      - Whether to remove the root certificates from the chain.
      - If not provided, this defaults to not removing the root certificates from the chain.
  user_ids:
    type: list
    required: false
    elements: str
    description:
      - The list of user IDs (OID 0.9.2342.19200300.100.1.1) to include in the signed certificate.
      - If not provided, no user IDs will be included.
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

try:
    import hvac
except ImportError:
    HAS_HVAC = False
    HVAC_IMPORT_ERROR = traceback.format_exc()
else:
    HAS_HVAC = True
    HVAC_IMPORT_ERROR = None

from ansible.module_utils.basic import missing_required_lib

from typing import Optional

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
        enforce_leaf_not_after_behavior=dict(type='bool', required=False),
        ttl=dict(type='str', required=False),
        format=dict(type='str', required=False, default='pem', choices=['pem', 'der', 'pem_bundle']),
        not_after=dict(type='str', required=False),
        signature_bits=dict(type='int', required=False, choices=[256, 384, 512]),
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

    def get_defined_extra_params(self) -> Optional[dict]:
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

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    engine_mount_point: str = module.params['engine_mount_point']
    role_name: str = module.params['role_name']
    csr: str = module.params['csr']

    extra_params: Optional[dict] = module.get_defined_extra_params()

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
