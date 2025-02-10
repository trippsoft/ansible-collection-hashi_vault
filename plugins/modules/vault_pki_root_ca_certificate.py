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
from ..module_utils._vault_cert import other_sans_to_list_of_str
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIRootCACertificateModule(VaultModule):
    """
    Vault PKI Root CA Certificate Module
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
        common_name=dict(type='str', required=False),
        export_private_key=dict(type='bool', required=False, default=False),
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
        ttl=dict(type='str', required=False),
        format=dict(type='str', required=False, choices=['pem', 'der', 'pem_bundle']),
        private_key_format=dict(type='str', required=False, choices=['der', 'pkcs8']),
        key_type=dict(type='str', required=False, choices=['rsa', 'ec']),
        key_bits=dict(type='int', required=False, choices=[224, 256, 384, 521, 2048, 3072, 4096, 8192]),
        max_path_length=dict(type='int', required=False),
        exclude_cn_from_sans=dict(type='bool', required=False),
        permitted_dns_domains=dict(type='list', required=False, elements='str'),
        ou=dict(type='list', required=False, elements='str'),
        organization=dict(type='list', required=False, elements='str'),
        country=dict(type='list', required=False, elements='str'),
        locality=dict(type='list', required=False, elements='str'),
        province=dict(type='list', required=False, elements='str'),
        street_address=dict(type='list', required=False, elements='str'),
        postal_code=dict(type='list', required=False, elements='str'),
        serial_number=dict(type='str', required=False)
    )

    DURATION_PARAMS = ['ttl']

    LIST_PARAMS_TO_JOIN = ['alt_names']

    def __init__(self, *args, **kwargs):

        argspec = self.ARGSPEC.copy()

        super(VaultPKIRootCACertificateModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            required_if=[
                ('state', 'present', ['common_name'])
            ],
            **kwargs
        )

    def read_certificate_data(self) -> str | None:
        """
        Read the current root CA certificate data from the Vault server.

        Returns:
            str | None: The root CA certificate data, or None if no certificate exists.
        """

        engine_mount_point: str = self.params['engine_mount_point']

        try:
            response: str = self.client.secrets.pki.read_ca_certificate(mount_point=engine_mount_point)
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message="Failed to read root CA certificate.",
                    exception=traceback.format_exc()
                )
            )

        if response == '':
            return None

        return response

    def build_request_payload(self) -> dict:
        """
        Build the request payload for the module.

        Returns:
            dict: The request payload.
        """

        engine_mount_point: str = self.params['engine_mount_point']
        common_name: str = self.params['common_name']
        export_private_key: bool = self.params['export_private_key']

        type = 'exported' if export_private_key else 'internal'

        extra_params = dict()

        for key, value in self.params.items():
            if key not in self.ARGSPEC:
                continue

            if key in ['engine_mount_point', 'state', 'common_name', 'export_private_key']:
                continue

            if value is None:
                continue

            if key == 'other_sans':
                extra_params[key] = other_sans_to_list_of_str(value)

            if key in self.DURATION_PARAMS:
                extra_params[key] = duration_str_to_seconds(value)
            elif key in self.LIST_PARAMS_TO_JOIN:
                extra_params[key] = self.convert_list_to_comma_separated_string(value)

        payload = dict(
            type=type,
            mount_point=engine_mount_point,
            common_name=common_name,
            extra_params=extra_params
        )

        return payload


def ensure_certificate_absent(
        module: VaultPKIRootCACertificateModule,
        certificate_data: str | None) -> dict:
    """
    Ensure that the root CA certificate is absent.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (str | None): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if certificate_data is None:
        return dict(changed=False)

    if not module.check_mode:
        try:
            response = module.client.secrets.pki.delete_root(mount_point=engine_mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message="Failed to delete root CA certificate.",
                    exception=traceback.format_exc()
                )
            )

        if response.get("warnings") is not None and len(response["warnings"]) > 0:
            warnings: list[str] = response["warnings"]

            for warning in warnings:
                # Skip the warning about deleting all keys and issuers
                if warning != "DELETE /root deletes all keys and issuers; prefer the new DELETE /key/:key_ref and DELETE /issuer/:issuer_ref for finer granularity, unless removal of all keys and issuers is desired.":
                    module.warn(warning)

    return dict(changed=True, prev_certificate=certificate_data)


def ensure_certificate_present(
        module: VaultPKIRootCACertificateModule,
        certificate_data: str | None) -> dict:
    """
    Ensure that the root CA certificate is present.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (str | None): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """

    if certificate_data is not None:
        return dict(changed=False)

    if module.check_mode:
        return dict(changed=True)

    payload = module.build_request_payload()

    try:
        response = module.client.secrets.pki.generate_root(**payload)
    except Exception:
        module.handle_error(
            VaultModuleError(
                message="Failed to generate root CA certificate.",
                exception=traceback.format_exc()
            )
        )

    if response.get("warnings") is not None and len(response["warnings"]) > 0:
        warnings: list[str] = response["warnings"]

        for warning in warnings:
            module.warn(warning)

    result = dict(
        changed=True,
        certificate=response["data"]["certificate"]
    )

    if "private_key" in response["data"]:
        result['private_key'] = response["data"]["private_key"]

    return result


def run_module():

    module = VaultPKIRootCACertificateModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params['state']

    module.initialize_client()

    certificate_data = module.read_certificate_data()

    if state == 'present':
        result = ensure_certificate_present(module, certificate_data)
    else:
        result = ensure_certificate_absent(module, certificate_data)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
