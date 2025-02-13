#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_kv2_secret_engine
version_added: 1.0.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures a KV version 2 secret engine in HashiCorp Vault.
description:
  - >-
    Ensures a L(KV version 2 secret engine,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/kv_v2.html)
    is configured as expected in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
  - trippsc2.hashi_vault.secret_engine
options:
  max_versions:
    type: int
    required: false
    description:
      - The maximum number of versions to keep for each secret.
      - If set to V(0), the 10 versions will be kept.
      - If not provided, this defaults to V(10) on new secret engines.
  cas_required:
    type: bool
    required: false
    description:
      - Whether to require the use of a Check-And-Set (CAS) parameter for write operations.
  delete_version_after:
    type: str
    required: false
    description:
      - The duration after which a version is deleted.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - If set to V(0), versions will not be deleted.
      - If not provided, this will default to V(0) on new secret engines.
"""

EXAMPLES = r"""
- name: Create a new KV version 2 secret engine
  trippsc2.hashi_vault.vault_kv2_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: present

- name: Remove a KV version 2 secret engine
  trippsc2.hashi_vault.vault_kv2_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: secret
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned: O(state=present)
  description:
    - The configuration of the secret engine.
  sample:
    description: 'The KV2 secret engine.'
    default_lease_ttl: 2678400
    max_lease_ttl: 2678400
    audit_non_hmac_request_keys: []
    audit_non_hmac_response_keys: []
    listing_visibility: unauth
    passthrough_request_headers: []
    max_versions: 10
    cas_required: false
    delete_version_after: 0
  contains:
    description:
      type: str
      description:
        - The description of the secret engine.
    default_lease_ttl:
      type: int
      description:
        - The default lease TTL of the secret engine in seconds.
    max_lease_ttl:
      type: int
      description:
        - The maximum lease TTL of the secret engine in seconds.
    audit_non_hmac_request_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC request keys to audit.
    audit_non_hmac_response_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC response keys to audit.
    listing_visibility:
      type: str
      description:
        - The listing visibility of the secret engine.
    passthrough_request_headers:
      type: list
      elements: str
      description:
        - The list of request headers to pass through.
    max_versions:
      type: int
      description:
        - The maximum number of versions to keep for each secret.
    cas_required:
      type: bool
      description:
        - Whether to require the use of a Check-And-Set (CAS) parameter for write operations.
    delete_version_after:
      type: str
      description:
        - The duration after which a version is deleted.
prev_config:
  description:
    - The previous configuration of the secret engine.
  type: dict
  returned: changed
  sample:
    description: 'The KV2 secret engine.'
    default_lease_ttl: 2678400
    max_lease_ttl: 2678400
    audit_non_hmac_request_keys: []
    audit_non_hmac_response_keys: []
    listing_visibility: unauth
    passthrough_request_headers: []
    max_versions: 10
    cas_required: false
    delete_version_after: 0
  contains:
    description:
      type: str
      description:
        - The description of the secret engine.
    default_lease_ttl:
      type: int
      description:
        - The default lease TTL of the secret engine in seconds.
    max_lease_ttl:
      type: int
      description:
        - The maximum lease TTL of the secret engine in seconds.
    audit_non_hmac_request_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC request keys to audit.
    audit_non_hmac_response_keys:
      type: list
      elements: str
      description:
        - The list of non-HMAC response keys to audit.
    listing_visibility:
      type: str
      description:
        - The listing visibility of the secret engine.
    passthrough_request_headers:
      type: list
      elements: str
      description:
        - The list of request headers to pass through.
    max_versions:
      type: int
      description:
        - The maximum number of versions to keep for each secret.
    cas_required:
      type: bool
      description:
        - Whether to require the use of a Check-And-Set (CAS) parameter for write operations.
    delete_version_after:
      type: str
      description:
        - The duration after which a version is deleted.
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

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module_error import VaultModuleError
from ..module_utils._vault_secret_engine_module import VaultSecretEngineModule


class VaultKV2SecretEngineModule(VaultSecretEngineModule):
    """
    Vault KV version 2 secret engine module.
    """

    KV2_ARGSPEC = dict(
        max_versions=dict(type='int', required=False, default=None),
        cas_required=dict(type='bool', required=False, default=None),
        delete_version_after=dict(type='str', required=False, default=None)
    )

    def __init__(
            self,
            *args,
            **kwargs):

        argspec = self.KV2_ARGSPEC.copy()

        super(VaultKV2SecretEngineModule, self).__init__(
            *args,
            argument_spec=argspec,
            backend_type='kv-v2',
            **kwargs
        )

    def get_defined_kv2_config_params(self) -> dict:
        """
        Get the defined configuration parameters for the KV version 2 secret engine.

        Returns:
            dict: The defined configuration parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys = [key for key in filtered_params.keys() if key not in self.KV2_ARGSPEC.keys()]

        for key in delete_keys:
            del filtered_params[key]

        delete_keys = [key for key in filtered_params.keys() if filtered_params[key] is None]

        for key in delete_keys:
            del filtered_params[key]

        if 'delete_version_after' in filtered_params:
            filtered_params['delete_version_after'] = duration_str_to_seconds(filtered_params['delete_version_after'])

        return filtered_params

    def format_kv2_config_data(self, config_data: dict):
        """
        Format the configuration data of a KV version 2 secret engine.

        Args:
            config_data (dict): The configuration data to format.

        Returns:
            dict: The formatted configuration data.
        """

        formatted_config_data: dict = {}

        for key, value in config_data.items():
            if key == 'delete_version_after':
                formatted_config_data[key] = duration_str_to_seconds(value, 0)
            else:
                formatted_config_data[key] = value

        return formatted_config_data

    def get_formatted_kv2_config(self) -> dict | None:
        """
        Read the configuration of the KV version 2 secret engine.
        """

        mount_point: str = self.params['engine_mount_point']

        try:
            config: dict = self.client.secrets.kv.v2.read_configuration(mount_point=mount_point)
        except hvac.exceptions.InvalidPath:
            return None
        except hvac.exceptions.UnexpectedError:
            return None
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission Denied to path '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error reading KV2 secret configuration '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

        formatted_config: dict = self.format_kv2_config_data(config.get('data', {}))

        return formatted_config

    def compare_kv2_config(self, previous_config: dict, desired_config: dict) -> dict:
        """
        Compare the configuration of a KV version 2 secret engine.

        Args:
            previous_config (dict): The previous configuration of the KV version 2 secret engine.
            desired_config (dict): The desired configuration of the KV version 2 secret engine.

        Returns:
            dict: The differences between the previous and desired configurations.
        """

        config_diff: dict = {}

        for key, value in desired_config.items():
            if key not in previous_config:
                if key == 'delete_version_after':
                    if value != 0:
                        config_diff[key] = value
                elif key == 'cas_required':
                    if value:
                        config_diff[key] = value
                elif key == 'max_versions':
                    if value != 0:
                        config_diff[key] = value
                else:
                    config_diff[key] = value
            else:
                if value != previous_config[key]:
                    config_diff[key] = value

        return config_diff

    def configure_kv2_secret_engine(self, config: dict) -> None:
        """
        Configure a KV version 2 secret engine.

        Args:
            config (dict): The configuration to apply to the secret engine.
        """

        mount_point: str = self.params['engine_mount_point']

        if self.check_mode:
            return None

        try:
            self.client.secrets.kv.v2.configure(mount_point=mount_point, **config)
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission Denied to path '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error configuring KV version 2 secret engine '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )


def ensure_engine_absent(
        module: VaultKV2SecretEngineModule,
        previous_mount_config: dict | None,
        previous_kv2_config: dict | None) -> dict:
    """
    Ensure that the secret engine is absent.

    Args:
        module (VaultKV2SecretEngineModule): The module object.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_kv2_config (dict): The previous configuration of the KV version 2 secret engine.

    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if previous_mount_config is None:
        return dict(changed=False)

    if previous_kv2_config is None:
        module.handle_error(
            VaultModuleError(
                message=f"The secret engine at '{engine_mount_point}' is not a KV version 2 secret engine"
            )
        )

    module.disable_mount()

    return dict(changed=True, prev_config=dict(**previous_mount_config, **previous_kv2_config))


def ensure_engine_present(
        module: VaultKV2SecretEngineModule,
        previous_mount_config: dict | None,
        previous_kv2_config: dict | None,
        desired_mount_config: dict,
        desired_kv2_config: dict) -> dict:
    """
    Ensure that the secret engine is present.

    Args:
        module (VaultKV2SecretEngineModule): The module object.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_kv2_config (dict): The previous configuration of the KV version 2 secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.
        desired_kv2_config (dict): The desired configuration of the KV version 2 secret engine.

    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    engine_mount_point: str = module.params['engine_mount_point']
    replace_non_kv2_secret_engine: bool = module.params['replace_different_backend_type']

    if previous_mount_config is None:

        description = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)
        module.configure_kv2_secret_engine(desired_kv2_config)

        return dict(
            changed=True,
            config=dict(
                description=description,
                **desired_mount_config,
                **desired_kv2_config
            )
        )

    if previous_kv2_config is None:
        if not replace_non_kv2_secret_engine:
            module.handle_error(
                VaultModuleError(
                    message=f"The secret engine at '{engine_mount_point}' is not a KV version 2 secret engine"
                )
            )

        module.disable_mount()

        description = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)
        module.configure_kv2_secret_engine(desired_kv2_config)

        return dict(
            changed=True,
            config=dict(description=description, **desired_mount_config, **desired_kv2_config)
        )

    changed = False

    mount_config_diff = module.compare_mount_config(
        previous_mount_config,
        desired_mount_config
    )

    if mount_config_diff:

        changed = True
        module.configure_mount(mount_config_diff)

    kv2_config_diff = module.compare_kv2_config(
        previous_kv2_config,
        desired_kv2_config
    )

    if kv2_config_diff:

        changed = True
        module.configure_kv2_secret_engine(kv2_config_diff)

    if changed:
        return dict(
            changed=changed,
            prev_config=dict(**previous_mount_config, **previous_kv2_config),
            config=dict(**desired_mount_config, **desired_kv2_config)
        )

    return dict(changed=False, config=dict(**previous_mount_config, **previous_kv2_config))


def run_module():

    module = VaultKV2SecretEngineModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params.get('state')

    desired_mount_config = module.get_defined_mount_config_params()
    desired_kv2_config = module.get_defined_kv2_config_params()

    module.initialize_client()

    previous_mount_config = module.get_formatted_mount_config()
    previous_kv2_config = module.get_formatted_kv2_config()

    if state == 'absent':
        result = ensure_engine_absent(
            module,
            previous_mount_config,
            previous_kv2_config
        )

    if state == 'present':
        result = ensure_engine_present(
            module,
            previous_mount_config,
            previous_kv2_config,
            desired_mount_config,
            desired_kv2_config
        )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
