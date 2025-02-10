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

from ..module_utils._vault_secret_engine_module import VaultSecretEngineModule
from ..module_utils._vault_module_error import VaultModuleError


def ensure_engine_absent(
        module: VaultSecretEngineModule,
        previous_mount_config: dict | None,
        previous_backend_type: str | None) -> dict:
    """
    Ensure that a secret engine is absent.

    Args:
        module (VaultSecretEngineModule): The module object.
        previous_mount_config (dict): The configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.

    Returns:
        dict: The result of the operation.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if previous_mount_config is None:
        return dict(changed=False)

    if previous_backend_type is None or previous_backend_type != 'database':
        module.handle_error(
            VaultModuleError(
                message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a Database secret engine"
            )
        )

    module.disable_mount()

    return dict(changed=True, prev_config=previous_mount_config)


def ensure_engine_present(
        module: VaultSecretEngineModule,
        previous_mount_config: dict | None,
        previous_backend_type: str | None,
        desired_mount_config: dict) -> dict:
    """
    Ensure that the secret engine is present.

    Args:
        module (VaultSecretEngineModule): The module object.
        previous_mount_config (dict): The previous configuration of the secret engine.
        previous_backend_type (str): The backend type of the secret engine.
        desired_mount_config (dict): The desired configuration of the secret engine.
        replace_non_database_secret_engine (bool): Whether to replace a non-Database secret engine.

    Returns:
        dict: The result of the operation to be sent to Ansible.
    """

    engine_mount_point: str = module.params['engine_mount_point']
    replace_non_database_secret_engine: bool = module.params['replace_different_backend_type']

    if previous_mount_config is None:

        description = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)

        return dict(changed=True, config=dict(description=description, **desired_mount_config))

    if previous_backend_type is None or previous_backend_type != 'database':
        if not replace_non_database_secret_engine:
            module.handle_error(
                VaultModuleError(
                    message=f"The secret engine at '{engine_mount_point}' has backend '{previous_backend_type}' that is not a Database secret engine"
                )
            )

        module.disable_mount()

        description = desired_mount_config.pop('description', None)

        module.enable_mount(desired_mount_config)

        return dict(changed=True, config=dict(description=description, **desired_mount_config))

    mount_config_diff = module.compare_mount_config(
        previous_mount_config,
        desired_mount_config
    )

    if mount_config_diff:
        module.configure_mount(mount_config_diff)

        return dict(
            changed=True,
            prev_config=previous_mount_config,
            config=desired_mount_config
        )

    return dict(changed=False, config=previous_mount_config)


def run_module():
    module = VaultSecretEngineModule(backend_type='database')

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params.get('state')

    desired_mount_config = module.get_defined_mount_config_params()

    module.initialize_client()

    previous_mount_config = module.get_formatted_mount_config()
    previous_backend_type = module.get_mount_backend_type()

    if state == 'absent':
        result = ensure_engine_absent(
            module,
            previous_mount_config,
            previous_backend_type
        )

    if state == 'present':
        result = ensure_engine_present(
            module,
            previous_mount_config,
            previous_backend_type,
            desired_mount_config
        )

    module.exit_json(**result)


def main():
    run_module()


if __name__ == '__main__':
    main()
