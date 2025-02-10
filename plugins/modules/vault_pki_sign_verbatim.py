#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

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

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

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
