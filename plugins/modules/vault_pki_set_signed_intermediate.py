#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_set_signed_intermediate
version_added: 1.5.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Sets a signed intermediate CA certificate for a PKI secret engine
description:
  - >-
    L(Sets a signed intermediate CA certificate,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html#set-signed-intermediate)
    for a PKI secret engine.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
options:
  certificate:
    type: str
    required: true
    description:
      - The PEM-encoded signed intermediate CA certificate.
      - This can include the signing certificate chain.
"""

EXAMPLES = r"""
- name: Set signed intermediate CA certificate for PKI secret engine
  trippsc2.hashi_vault.vault_pki_set_signed_intermediate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    certificate: '{{ signed_intermediate_certificate }}'
"""

RETURN = r"""
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

from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKISetSignedIntermediateModule(VaultModule):
    def __init__(self):
        argument_spec = dict(
            engine_mount_point=dict(required=True, type='str'),
            certificate=dict(required=True, type='str')
        )

        super(VaultPKISetSignedIntermediateModule, self).__init__(
            argument_spec=argument_spec,
            supports_check_mode=True,
        )

    def get_existing_certificate(self) -> str:
        """
        Get the existing certificate for the PKI secret engine.

        Returns:
            str: The existing certificate.
        """

        engine_mount_point: str = self.params['engine_mount_point']

        try:
            response = self.client.secrets.pki.read_ca_certificate_chain(
                mount_point=engine_mount_point
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message='Failed to get existing certificate for PKI secret engine',
                    details=traceback.format_exc()
                )
            )

        return response

    def build_request_payload(self) -> dict:
        """
        Build the request payload for the module.

        Returns:
            dict: The request payload.
        """

        engine_mount_point: str = self.params['engine_mount_point']
        certificate: str = self.params['certificate']

        payload = dict(
            mount_point=engine_mount_point,
            certificate=certificate
        )

        return payload


def run_module():

    module = VaultPKISetSignedIntermediateModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    certificate: str = module.params['certificate']
    certificate = certificate.rstrip()
    existing_certificate = module.get_existing_certificate()

    if existing_certificate == certificate:
        module.exit_json(changed=False)

    if module.check_mode:
        module.exit_json(changed=True)

    try:
        payload = module.build_request_payload()
        response = module.client.secrets.pki.set_signed_intermediate(**payload)
    except Exception:
        module.handle_error(
            VaultModuleError(
                message='Failed to set signed intermediate CA certificate for PKI secret engine',
                details=traceback.format_exc()
            )
        )

    if response.get("warnings") is not None and len(response["warnings"]) > 0:
        warnings: list[str] = response["warnings"]

        for warning in warnings:
            module.warn(warning)

    module.exit_json(changed=True)


def main():
    run_module()


if __name__ == '__main__':
    main()
