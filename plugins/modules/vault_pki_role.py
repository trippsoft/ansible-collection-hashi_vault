#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import traceback

try:
    import hvac
    import hvac.exceptions
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

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

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
