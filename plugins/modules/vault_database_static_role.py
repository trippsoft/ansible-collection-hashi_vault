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


class VaultDatabaseStaticRole(VaultModule):
    """
    Vault Database Static Role Module
    """

    ARGSPEC = dict(
        engine_mount_point=dict(type='str', required=True),
        state=dict(type='str', choices=['present', 'absent'], default='present'),
        name=dict(type='str', required=True),
        db_name=dict(type='str', required=False),
        db_username=dict(type='str', required=False),
        rotation_statements=dict(type='list', elements='str', required=False),
        rotation_period=dict(type='str', required=False)
    )

    DEFAULT_VALUES = dict(
        rotation_statements=[],
        rotation_period='86400'
    )

    def __init__(self, *args, **kwargs):

        argspec = self.ARGSPEC.copy()

        super(VaultDatabaseStaticRole, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            required_if=[
                ('state', 'present', ['db_name', 'db_username'])
            ],
            **kwargs
        )

    def get_formatted_role_data(self) -> dict | None:
        """
        Get the formatted role data from the Vault server.
        """

        name = self.params['name']
        mount_point = self.params['engine_mount_point']

        try:
            role_data = self.client.secrets.database.read_static_role(
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

        data = role_data["data"]

        delete_keys = [key for key in data.keys() if key not in self.DEFAULT_VALUES.keys() and key != 'username' and key != 'db_name']

        for key in delete_keys:
            del data[key]

        return data

    def get_defined_role_params(self, previous_role_data: dict | None) -> dict:
        """
        Get the defined role parameters.

        Args:
            previous_role_data (dict | None): The previous role data.

        Returns:
            dict: The defined role parameters.
        """

        filtered_params = self.params.copy()

        delete_keys = [key for key in filtered_params.keys() if key not in self.DEFAULT_VALUES.keys()]

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


def ensure_role_absent(module: VaultDatabaseStaticRole, previous_role_data: dict | None) -> dict:
    """
    Ensure the role is absent.

    Args:
        module (VaultDatabaseStaticRole): The module object.
        previous_role_data (dict | None): The previous role data.

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
        previous_role_data: dict | None,
        desired_role_data: dict) -> dict:
    """
    Ensure the role is present.

    Args:
        module (VaultDatabaseStaticRole): The module object.
        previous_role_data (dict | None): The previous role data.
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


def run_module():

    module = VaultDatabaseStaticRole()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    module.initialize_client()

    state: str = module.params['state']

    previous_role_data = module.get_formatted_role_data()
    desired_role_data = module.get_defined_role_params(previous_role_data)

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
