#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_ssh_otp_role
version_added: 1.10.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures an SSH one-time-password role in HashiCorp Vault
description:
  - >-
    Ensures an L(SSH one-time-password role,https://python-hvac.org/en/stable/source/hvac_api_secrets_engines.html#hvac.api.secrets_engines.Ssh.create_role)
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
  overwrite_non_otp_role:
    type: bool
    required: false
    default: false
    description:
      - Whether to overwrite a non-OTP role with the same name.
  allowed_users:
    type: list
    required: false
    elements: str
    description:
      - A list of users that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty list will allow all users.
      - If not provided and the role does not already exist, this will default to an empty list.
  cidr_list:
    type: list
    required: false
    elements: str
    description:
      - A list of CIDR blocks that are allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty list will allow all CIDR blocks.
      - If not provided and the role does not already exist, this will default to an empty list.
  default_user:
    type: str
    required: false
    description:
      - The default user when using this role.
      - If O(state=absent), this is ignored.
      - If O(state=present), this is required.
  exclude_cidr_list:
    type: list
    required: false
    elements: str
    description:
      - A list of CIDR blocks that are not allowed to use this role.
      - If O(state=absent), this is ignored.
      - Providing an empty list will not exclude any CIDR blocks.
      - If not provided and the role does not already exist, this will default to an empty list.
  port:
    type: int
    required: false
    description:
      - The port to use for SSH connections.
      - If O(state=absent), this is ignored.
      - If not provided and the role does not already exist, this will default to 22.
"""

EXAMPLES = r"""
- name: Create an SSH role
  trippsc2.hashi_vault.vault_ssh_otp_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    name: my-role
    default_user: my-user
    state: present

- name: Remove an SSH role
  trippsc2.hashi_vault.vault_ssh_otp_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: ssh
    name: my-role
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned: O(state=present)
  description:
    - The configuration of the SSH role.
  sample:
    allowed_users: []
    cidr_list: []
    default_user: my-user
    exclude_cidr_list: []
    port: 22
  contains:
    allowed_users:
      type: list
      elements: str
      description:
        - A list of users that are allowed to use this role.
    cidr_list:
      type: list
      elements: str
      description:
        - A list of CIDR blocks that are allowed to use this role.
    default_user:
      type: str
      description:
        - The default user when using this role.
    exclude_cidr_list:
      type: list
      elements: str
      description:
        - A list of CIDR blocks that are not allowed to use this role.
    key_type:
      type: str
      description:
        - The type of key to use for the role.
        - This is always be V(otp).
    port:
      type: int
      description:
        - The port to use for SSH connections.
prev_config:
  type: dict
  returned: changed
  description:
    - The previous configuration of the SSH role.
  sample:
    allowed_users: []
    cidr_list: []
    default_user: my-user
    exclude_cidr_list: []
    port: 22
  contains:
    allowed_users:
      type: list
      elements: str
      description:
        - A list of users that are allowed to use this role.
    cidr_list:
      type: list
      elements: str
      description:
        - A list of CIDR blocks that are allowed to use this role.
    default_user:
      type: str
      description:
        - The default user when using this role.
    exclude_cidr_list:
      type: list
      elements: str
      description:
        - A list of CIDR blocks that are not allowed to use this role.
    key_type:
      type: str
      description:
        - The type of key to use for the role.
    port:
      type: int
      description:
        - The port to use for SSH connections.
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

from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultSSHOTPRoleModule(VaultModule):
    """
    Vault SSH one-time-password role module.
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        name=dict(type='str', required=True),
        state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
        overwrite_non_otp_role=dict(type='bool', required=False, default=False),
        allowed_users=dict(type='list', elements='str', required=False),
        cidr_list=dict(type='list', elements='str', required=False),
        default_user=dict(type='str', required=False),
        exclude_cidr_list=dict(type='list', elements='str', required=False),
        port=dict(type='int', required=False)
    )

    DEFAULT_VALUES: dict = dict(
        allowed_users=[],
        cidr_list=[],
        default_user=None,
        exclude_cidr_list=[],
        port=22
    )

    SET_COMPARE_PARAMS: List[str] = [
        'allowed_users',
        'cidr_list',
        'exclude_cidr_list'
    ]

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultSSHOTPRoleModule, self).__init__(
            *args,
            argument_spec=argspec,
            required_if=[
                ('state', 'present', ['default_user'])
            ],
            supports_check_mode=True,
            **kwargs
        )

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

        delete_keys: List[str] = [key for key, value in filtered_params.items() if value is None]

        for key in delete_keys:
            del filtered_params[key]

        filtered_params['key_type'] = 'otp'

        return filtered_params

    def format_role_data(self, config_data: dict) -> dict:
        """
        Format the data for an SSH one-time-password role.

        Args:
            config_data (dict): The data to format.

        Returns:
            dict: The formatted data.
        """

        formatted_config_data: dict = {}

        key_type: str = config_data['key_type']

        formatted_config_data['key_type'] = key_type

        if key_type != 'otp':
            return formatted_config_data

        for key, value in config_data.items():
            if key in self.DEFAULT_VALUES:
                if key in self.SET_COMPARE_PARAMS:
                    formatted_config_data[key] = value.split(',')
                else:
                    formatted_config_data[key] = value

        return formatted_config_data

    def get_formatted_role_data(self) -> Optional[dict]:
        """
        Get the formatted data for an SSH one-time-password role.

        Returns:
            dict: The formatted data for the SSH one-time-password role.
        """

        name: str = self.params['name']
        mount_point: str = self.params['engine_mount_point']

        try:
            config: dict = self.client.secrets.ssh.read_role(name=name, mount_point=mount_point)
        except hvac.exceptions.InvalidPath:
            return None
        except hvac.exceptions.UnexpectedError:
            return None
        except hvac.exceptions.Forbidden:
            self.handle_error(
                VaultModuleError(
                    message=f"Forbidden: Permission denied to read SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Error reading SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

        formatted_config: dict = self.format_role_data(config.get('data', dict()))

        return formatted_config

    def compare_role(self, previous_config: dict, desired_config: dict) -> dict:
        """
        Compare the previous and desired configurations of an SSH one-time-password role.

        Args:
            previous_config (dict): The previous configuration of the SSH one-time-password role.
            desired_config (dict): The desired configuration of the SSH one-time-password role.

        Returns:
            dict: The comparison of the previous and desired configurations.
        """

        if previous_config['key_type'] != desired_config['key_type']:
            return desired_config

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

        return config_diff

    def format_payload(self, config_data: dict) -> dict:
        """
        Format the payload for an SSH one-time-password role.

        Args:
            config_data (dict): The data to format.

        Returns:
            dict: The formatted payload.
        """

        formatted_payload: dict = {}

        for key, value in config_data.items():
            if key in self.SET_COMPARE_PARAMS:
                formatted_payload[key] = ','.join(value)
            else:
                formatted_payload[key] = value

        formatted_payload['key_type'] = 'otp'
        formatted_payload['default_user'] = self.params['default_user']

        return formatted_payload


def ensure_role_absent(module: VaultSSHOTPRoleModule, previous_role_data: Optional[dict]) -> dict:
    """
    Ensure an SSH one-time-password role is absent.

    Args:
        module (VaultSSHOTPRoleModule): The module instance.
        previous_role_data (Optional[dict]): The previous role data.

    Returns:
        dict: The result of the operation.
    """

    if previous_role_data is None:
        return dict(changed=False)

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']
    overwrite_non_otp_role: bool = module.params['overwrite_non_otp_role']

    if previous_role_data['key_type'] != 'otp' and not overwrite_non_otp_role:
        module.handle_error(
            VaultModuleError(
                message=f"SSH role '{name}' at mount point '{mount_point}' is not an OTP role and overwrite_non_otp_role is not set",
                exception=traceback.format_exc()
            )
        )

    if not module.check_mode:
        try:
            module.client.secrets.ssh.delete_role(name=name, mount_point=mount_point)
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error deleting SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_role=previous_role_data)


def ensure_role_present(module: VaultSSHOTPRoleModule, previous_role_data: Optional[dict], desired_role_data: dict) -> dict:
    """
    Ensure an SSH one-time-password role is present.

    Args:
        module (VaultSSHOTPRoleModule): The module instance.
        previous_role_data (Optional[dict]): The previous role data.
        desired_role_data (dict): The desired role data.

    Returns:
        dict: The result of the operation.
    """

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']
    overwrite_non_otp_role: bool = module.params['overwrite_non_otp_role']

    if previous_role_data is None:

        if not module.check_mode:
            try:
                module.client.secrets.ssh.create_role(
                    name=name,
                    mount_point=mount_point,
                    **module.format_payload(desired_role_data)
                )
            except Exception:
                module.handle_error(
                    VaultModuleError(
                        message=f"Error creating SSH role '{name}' at mount point '{mount_point}'",
                        exception=traceback.format_exc()
                    )
                )

        return dict(changed=True, role=desired_role_data)

    if previous_role_data['key_type'] != 'otp' and not overwrite_non_otp_role:
        module.handle_error(
            VaultModuleError(
                message=f"SSH role '{name}' at mount point '{mount_point}' is not an OTP role and overwrite_non_otp_role is not set",
                exception=traceback.format_exc()
            )
        )

    config_diff: dict = module.compare_role(
        previous_role_data,
        desired_role_data
    )

    if not config_diff:
        return dict(changed=False, role=desired_role_data)

    if not module.check_mode:
        try:
            module.client.secrets.ssh.create_role(
                name=name,
                mount_point=mount_point,
                **module.format_payload(config_diff)
            )
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message=f"Error updating SSH role '{name}' at mount point '{mount_point}'",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_role=previous_role_data, role=desired_role_data)


def run_module() -> None:

    module: VaultSSHOTPRoleModule = VaultSSHOTPRoleModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR
        )

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
