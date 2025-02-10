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

from ..module_utils._vault_cert import other_sans_to_list_of_str
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIGenerateIntermediateCSRModule(VaultModule):
    """
    Vault PKI Generate Intermediate CA CSR Module
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        type=dict(type='str', required=False, default='internal', choices=['internal', 'existing']),
        key_ref=dict(type='str', required=False),
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
        format=dict(type='str', required=False, choices=['pem', 'der', 'pem_bundle']),
        private_key_format=dict(
            type='str',
            required=False,
            choices=['der', 'pkcs8'],
            default='der'
        ),
        key_type=dict(type='str', required=False, choices=['rsa', 'ed25519', 'ec']),
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
        key_name=dict(type='str', required=False),
        signature_bits=dict(type='int', required=False, choices=[256, 384, 512]),
        exclude_cn_from_sans=dict(type='bool', required=False),
        ou=dict(type='list', required=False, elements='str'),
        organization=dict(type='list', required=False, elements='str'),
        country=dict(type='list', required=False, elements='str'),
        locality=dict(type='list', required=False, elements='str'),
        province=dict(type='list', required=False, elements='str'),
        street_address=dict(type='list', required=False, elements='str'),
        postal_code=dict(type='list', required=False, elements='str'),
        serial_number=dict(type='str', required=False),
        add_basic_constraints=dict(type='bool', required=False),
        key_usage=dict(
            type='list',
            required=False,
            default=['CertSign', 'CRLSign'],
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
            ]
        )
    )

    LIST_PARAMS_TO_JOIN = ['alt_names']

    def __init__(self, *args, **kwargs):
        argspec = self.ARGSPEC.copy()

        super(VaultPKIGenerateIntermediateCSRModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            **kwargs
        )

    def build_request_payload(self) -> dict:
        """
        Build the request payload for the module.

        Returns:
            dict: The request payload.
        """

        engine_mount_point: str = self.params['engine_mount_point']
        type = self.params['type']
        common_name: str = self.params['common_name']

        extra_params = dict()

        for key, value in self.params.items():
            if key not in self.ARGSPEC:
                continue

            if key in ['engine_mount_point', 'type', 'common_name']:
                continue

            if value is None:
                continue

            if key == 'other_sans':
                extra_params[key] = other_sans_to_list_of_str(value)
                continue

            if key in self.LIST_PARAMS_TO_JOIN:
                extra_params[key] = self.convert_list_to_comma_separated_string(value)
                continue

            extra_params[key] = value

        payload = dict(
            type=type,
            mount_point=engine_mount_point,
            common_name=common_name,
            extra_params=extra_params
        )

        return payload


def run_module():

    module = VaultPKIGenerateIntermediateCSRModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    try:
        payload = module.build_request_payload()
        response = module.client.secrets.pki.generate_intermediate(**payload)
    except Exception:
        module.handle_error(
            VaultModuleError(
                message='Failed to generate intermediate CA CSR',
                details=traceback.format_exc()
            )
        )

    if response.get("warnings") is not None and len(response["warnings"]) > 0:
        warnings: list[str] = response["warnings"]

        for warning in warnings:
            module.warn(warning)

    result = dict(changed=True)

    for key, value in response["data"].items():
        result[key] = value

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
