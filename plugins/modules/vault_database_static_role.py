#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_database_static_role
version_added: 1.3.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures a Database static role in HashiCorp Vault
description:
  - >-
    Ensures a L(Database static role,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/database.html#create-static-role)
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
      - The name of the role to configured.
  state:
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
    description:
      - The expected state of the role.
  db_name:
    type: str
    required: false
    description:
      - Required if O(state=present).
      - The name of the database connection to use for this role.
  db_username:
    type: str
    required: false
    description:
      - Required if O(state=present).
      - The database username to use when connecting to the database system.
  rotation_statements:
    type: list
    required: false
    elements: str
    description:
      - A list of SQL statements to execute when rotating the database credentials.
      - If not provided, this defaults to an empty list on new roles.
  rotation_period:
    type: str
    required: false
    description:
      - The duration between rotations.
      - This value can be a duration string or a number of seconds.
      - If not provided, this defaults to V(86400s) on new roles.
"""

EXAMPLES = r"""
- name: Create database static role
  trippsc2.hashi_vault.vault_database_static_role:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: database
    name: my-role
    db_name: my-database
    db_username: testuser
    rotation_statements: []
    rotation_period: 30d
    state: present

- name: Remove database static role
  trippsc2.hashi_vault.vault_database_secret_engine:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: database
    name: my-role
    state: absent
"""

RETURN = r"""
config:
  type: dict
  returned: O(state=present)
  description:
    - The configuration of the role.
  contains:
    db_name:
      type: str
      description:
        - The name of the database connection to associate with the role.
    db_username:
      type: str
      description:
        - The username to use when connecting to the database.
    rotation_statements:
      type: list
      elements: str
      description:
        - The SQL statements to execute when rotating the database credentials.
    rotation_period:
      type: int
      description:
        - The duration between rotations.
prev_config:
  type: dict
  returned: changed
  description:
    - The previous configuration of the role.
  contains:
    db_name:
      type: str
      description:
        - The name of the database connection to associate with the role.
    db_username:
      type: str
      description:
        - The username to use when connecting to the database.
    rotation_statements:
      type: list
      elements: str
      description:
        - The SQL statements to execute when rotating the database credentials.
    rotation_period:
      type: int
      description:
        - The duration between rotations.
"""

import traceback

from ansible.module_utils.basic import missing_required_lib

from typing import Optional

try:
    import hvac
except ImportError:
    HAS_HVAC: bool = False
    HVAC_IMPORT_ERROR: Optional[str] = traceback.format_exc()
else:
    HAS_HVAC: bool = True
    HVAC_IMPORT_ERROR: Optional[str] = None

from ..module_utils._timeparse import duration_str_to_seconds
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultDatabaseStaticRole(VaultModule):
    """
    Vault Database Static Role Module
    """

    ARGSPEC: dict = dict(
        engine_mount_point=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        name=dict(type='str', required=True),
        db_name=dict(type='str', required=False),
        db_username=dict(type='str', required=False),
        rotation_statements=dict(type='list', elements='str', required=False),
        rotation_period=dict(type='str', required=False)
    )

    DEFAULT_VALUES: dict = dict(
        rotation_statements=[],
        rotation_period='86400'
    )

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultDatabaseStaticRole, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            required_if=[
                ('state', 'present', ['db_name', 'db_username'])
            ],
            **kwargs
        )

    def get_formatted_role_data(self) -> Optional[dict]:
        """
        Get the formatted role data from the Vault server.
        """

        name: str = self.params['name']
        mount_point: str = self.params['engine_mount_point']

        try:
            role_data: dict = self.client.secrets.database.read_static_role(
                name=name,
                mount_point=mount_point
            )
        except hvac.exceptions.InvalidPath:
            return None
        except Exception:
            self.handle_error(
                VaultModuleError(
                    message=f"Failed to read role '{name}' data at mount point '{mount_point}'.",
                    exception=traceback.format_exc()
                )
            )

        if role_data.get("data") is None:
            return None

        data: dict = role_data["data"]

        delete_keys: list[str] = [key for key in data.keys() if key not in self.DEFAULT_VALUES.keys() and key != 'username' and key != 'db_name']

        for key in delete_keys:
            del data[key]

        return data

    def get_defined_role_params(self, previous_role_data: Optional[dict]) -> dict:
        """
        Get the defined role parameters.

        Args:
            previous_role_data (Optional[dict]): The previous role data.

        Returns:
            dict: The defined role parameters.
        """

        filtered_params: dict = self.params.copy()

        delete_keys: list[str] = [key for key in filtered_params.keys() if key not in self.DEFAULT_VALUES.keys()]

        for key in delete_keys:
            del filtered_params[key]

        for key in filtered_params.keys():
            if filtered_params[key] is None:
                if previous_role_data is not None and previous_role_data.get(key) is not None:
                    filtered_params[key] = previous_role_data[key]
                else:
                    filtered_params[key] = self.DEFAULT_VALUES[key]
            elif key == 'rotation_period':
                filtered_params[key] = duration_str_to_seconds(filtered_params[key])

        return filtered_params


def ensure_role_absent(module: VaultDatabaseStaticRole, previous_role_data: Optional[dict]) -> dict:
    """
    Ensure the role is absent.

    Args:
        module (VaultDatabaseStaticRole): The module object.
        previous_role_data (Optional[dict]): The previous role data.

    Returns:
        dict: The result of the operation.
    """

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']

    if previous_role_data is None:
        return dict(changed=False)

    if not module.check_mode:
        try:
            module.client.secrets.database.delete_static_role(
                name=name,
                mount_point=mount_point
            )
        except Exception:
            module.handle_error(
                VaultModuleError(
                    message="Failed to delete role '{name}' at mount point '{mount_point}'.",
                    exception=traceback.format_exc()
                )
            )

    return dict(changed=True, prev_config=previous_role_data)


def ensure_role_present(
        module: VaultDatabaseStaticRole,
        previous_role_data: Optional[dict],
        desired_role_data: dict) -> dict:
    """
    Ensure the role is present.

    Args:
        module (VaultDatabaseStaticRole): The module object.
        previous_role_data (Optional[dict]): The previous role data.
        desired_role_data (dict): The desired role data.

    Returns:
        dict: The result of the operation.
    """

    name: str = module.params['name']
    mount_point: str = module.params['engine_mount_point']
    db_name: str = module.params['db_name']
    username: str = module.params['db_username']

    if previous_role_data is None:
        if not module.check_mode:
            try:
                module.client.secrets.database.create_static_role(
                    name=name,
                    db_name=db_name,
                    username=username,
                    mount_point=mount_point,
                    **desired_role_data
                )
            except Exception:
                module.handle_error(
                    VaultModuleError(
                        message=f"Failed to create role '{name}' at mount point '{mount_point}'.",
                        exception=traceback.format_exc()
                    )
                )

        return dict(changed=True, config=desired_role_data)

    previous_db_name: str = previous_role_data.pop("db_name")

    if previous_db_name != db_name:
        module.handle_error(
            VaultModuleError(
                message=f"Cannot change the database connection name for role '{name}' at mount point '{mount_point}'."
            )
        )

    previous_username: str = previous_role_data.pop("username")

    if previous_username != username:
        module.handle_error(
            VaultModuleError(
                message=f"Cannot change the username for role '{name}' at mount point '{mount_point}'."
            )
        )

    if previous_role_data != desired_role_data:
        if not module.check_mode:
            try:
                module.client.secrets.database.create_static_role(
                    name=name,
                    db_name=db_name,
                    username=username,
                    mount_point=mount_point,
                    **desired_role_data
                )
            except Exception:
                module.handle_error(
                    VaultModuleError(
                        message=f"Failed to update role '{name}' at mount point '{mount_point}'.",
                        exception=traceback.format_exc()
                    )
                )

        return dict(changed=True, prev_config=previous_role_data, config=desired_role_data)

    return dict(changed=False, config=previous_role_data)


def run_module() -> None:

    module: VaultDatabaseStaticRole = VaultDatabaseStaticRole()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    state: str = module.params['state']

    previous_role_data: Optional[dict] = module.get_formatted_role_data()
    desired_role_data: dict = module.get_defined_role_params(previous_role_data)

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
