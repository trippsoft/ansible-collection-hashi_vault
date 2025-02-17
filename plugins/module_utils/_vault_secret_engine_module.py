# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)

import traceback

from typing import Optional

from ._timeparse import duration_str_to_seconds
from ._vault_module import VaultModule
from ._vault_module_error import VaultModuleError

try:
    import hvac
except ImportError:
    HAS_HVAC = False
    HVAC_IMPORT_ERROR = traceback.format_exc()

    class VaultSecretEngineModule(VaultModule):
        pass

        ARGSPEC = dict(
            engine_mount_point=dict(type='str', required=True),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            replace_different_backend_type=dict(type='bool', required=False, default=False),
            description=dict(type='str', required=False, default=None),
            default_lease_ttl=dict(type='str', required=False, default=None),
            max_lease_ttl=dict(type='str', required=False, default=None),
            audit_non_hmac_request_keys=dict(type='list', required=False, default=None, elements='str'),
            audit_non_hmac_response_keys=dict(type='list', required=False, default=None, elements='str'),
            listing_visibility=dict(type='str', required=False, default=None, choices=['normal', 'unauth', 'hidden']),
            passthrough_request_headers=dict(type='list', required=False, default=None, elements='str')
        )

        DURATION_PARAMS: list[str] = ['default_lease_ttl', 'max_lease_ttl']

        DEFAULT_TTL = 2764800

        backend_type: str

        def __init__(
                self,
                *args,
                backend_type: str,
                argument_spec: dict = None,
                **kwargs):

            if argument_spec is None:
                argument_spec = dict()

            self.backend_type = backend_type

            argspec = self.ARGSPEC.copy()
            argspec.update(argument_spec)

            super(VaultSecretEngineModule, self).__init__(
                *args,
                argument_spec=argspec,
                supports_check_mode=True,
                **kwargs
            )

else:
    HAS_HVAC = True
    HVAC_IMPORT_ERROR = None

    class VaultSecretEngineModule(VaultModule):
        """
        Extends VaultModule to simplify the creation of Vault secret engine modules.
        """

        ARGSPEC = dict(
            engine_mount_point=dict(type='str', required=True),
            state=dict(type='str', required=False, default='present', choices=['present', 'absent']),
            replace_different_backend_type=dict(type='bool', required=False, default=False),
            description=dict(type='str', required=False, default=None),
            default_lease_ttl=dict(type='str', required=False, default=None),
            max_lease_ttl=dict(type='str', required=False, default=None),
            audit_non_hmac_request_keys=dict(type='list', required=False, default=None),
            audit_non_hmac_response_keys=dict(type='list', required=False, default=None),
            listing_visibility=dict(type='str', required=False, default=None, choices=['normal', 'unauth', 'hidden']),
            passthrough_request_headers=dict(type='list', required=False, default=None)
        )

        DURATION_PARAMS: list[str] = ['default_lease_ttl', 'max_lease_ttl']

        DEFAULT_TTL = 2764800

        backend_type: str

        def __init__(
                self,
                *args,
                backend_type: str,
                argument_spec: dict = None,
                **kwargs):

            if argument_spec is None:
                argument_spec = dict()

            self.backend_type = backend_type

            argspec = self.ARGSPEC.copy()
            argspec.update(argument_spec)

            super(VaultSecretEngineModule, self).__init__(
                *args,
                argument_spec=argspec,
                supports_check_mode=True,
                **kwargs
            )

        def get_defined_mount_config_params(self) -> dict:
            """
            Get the defined mount configuration parameters.

            Returns:
                dict: The defined mount configuration parameters.
            """

            filtered_params = self.params.copy()

            delete_keys = [key for key in filtered_params.keys() if key not in self.ARGSPEC]

            for key in delete_keys:
                del filtered_params[key]

            delete_keys = [key for key in filtered_params.keys() if key in ['engine_mount_point', 'state', 'replace_different_backend_type']]

            for key in delete_keys:
                del filtered_params[key]

            delete_keys = [key for key in filtered_params.keys() if self.params[key] is None]

            for key in delete_keys:
                del filtered_params[key]

            for key in self.DURATION_PARAMS:
                if key in filtered_params:
                    filtered_params[key] = duration_str_to_seconds(filtered_params[key])

            return filtered_params

        def get_mount_backend_type(self) -> Optional[str]:
            """
            Get the backend type of a secret engine at a given path.

            Returns:
                str: The backend type of the secret engine at the given path, if it exists.
            """

            mount_path: str = self.params['engine_mount_point']

            try:
                mounted_engines = self.client.sys.list_mounted_secrets_engines().get('data', {})
            except hvac.exceptions.Forbidden:
                self.handle_error(
                    VaultModuleError(
                        message="Forbidden: Permission Denied to list mounted engines",
                        exception=traceback.format_exc()
                    )
                )
            except Exception:
                self.handle_error(
                    VaultModuleError(
                        message="Error listing mounted engines",
                        exception=traceback.format_exc()
                    )
                )

            mount_data = mounted_engines.get(mount_path + '/', {})
            mount_type = mount_data.get('type', None)

            if mount_type == 'kv':
                version = mount_data.get('options', {}).get('version', "0")

                if (version == "1" or version == 1):
                    return 'kv-v1'
                elif (version == "2" or version == 2):
                    return 'kv-v2'
                return 'kv'

            return mount_type

        def format_mount_config_data(self, config_data: dict) -> dict:
            """
            Format the mount configuration data for a secret engine.

            Args:
                config_data (dict): The configuration data to format.

            Returns:
                dict: The formatted configuration data.
            """

            formatted_data = {}

            for key, value in config_data.items():
                if key != 'options':
                    formatted_data[key] = value

            return formatted_data

        def get_formatted_mount_config(self) -> Optional[dict]:
            """
            Read the configuration of the secret engine and format it.

            Returns:
                dict: The formatted configuration of the secret engine.
            """

            path: str = self.params['engine_mount_point']

            try:
                config: dict = self.client.sys.read_mount_configuration(path=path)
            except hvac.exceptions.InvalidRequest:
                return None
            except hvac.exceptions.Forbidden:
                self.handle_error(
                    VaultModuleError(
                        message=f"Forbidden: Permission Denied to path '{path}'",
                        exception=traceback.format_exc()
                    )
                )

            config_data: dict = config.get('data', {})

            config_data = self.format_mount_config_data(config_data)

            return config_data

        def compare_mount_config(self, previous_config: dict, desired_config: dict) -> dict:
            """
            Compare the configuration of a secret engine.

            Args:
                previous_config (dict): The previous configuration of the secret engine.
                desired_config (dict): The desired configuration of the secret engine.

            Returns:
                dict: The differences between the configurations.
            """

            differences: dict = {}

            for key, value in desired_config.items():
                if key not in previous_config:
                    if key == 'description':
                        if value != '':
                            differences[key] = value
                    elif (key == 'default_lease_ttl' or
                            key == 'max_lease_ttl'):
                        if value != self.DEFAULT_TTL:
                            differences[key] = value
                    elif (key == 'audit_non_hmac_request_keys' or
                            key == 'audit_non_hmac_response_keys' or
                            key == 'passthrough_request_headers'):
                        if value != []:
                            differences[key] = value
                    elif key == 'listing_visibility':
                        if value != 'normal':
                            differences[key] = value
                    else:
                        differences[key] = value
                else:
                    if (key == 'audit_non_hmac_request_keys' or
                            key == 'audit_non_hmac_response_keys' or
                            key == 'passthrough_request_headers'):

                        if set(value) != set(previous_config[key]):
                            differences[key] = value
                    else:
                        if value != previous_config[key]:
                            differences[key] = value

            return differences

        def disable_mount(self) -> None:
            """
            Disable the secret engine.
            """

            if self.check_mode:
                return None

            path: str = self.params['engine_mount_point']

            try:
                self.client.sys.disable_secrets_engine(path=path)
            except hvac.exceptions.Forbidden:
                self.handle_error(
                    VaultModuleError(
                        message=f"Forbidden: Permission Denied to path '{path}'",
                        exception=traceback.format_exc()
                    )
                )
            except Exception:
                self.handle_error(
                    VaultModuleError(
                        message=f"Error disabling mount '{path}'",
                        exception=traceback.format_exc()
                    )
                )

        def enable_mount(self, config: dict) -> None:
            """
            Enable the secret engine.

            Args:
                config (dict): The configuration of the secret engine.
            """

            if self.check_mode:
                return None

            path: str = self.params['engine_mount_point']
            description: Optional[str] = self.params['description']

            try:
                self.client.sys.enable_secrets_engine(
                    path=path,
                    backend_type=self.backend_type,
                    description=description,
                    config=config
                )
            except hvac.exceptions.Forbidden:
                self.handle_error(
                    VaultModuleError(
                        message=f"Forbidden: Permission Denied to path '{path}'",
                        exception=traceback.format_exc()
                    )
                )
            except Exception:
                self.handle_error(
                    VaultModuleError(
                        message=f"Error enabling mount '{path}'",
                        exception=traceback.format_exc()
                    )
                )

        def configure_mount(self, config: dict) -> None:
            """
            Configure a secret engine at a given path.

            Args:
                config (dict): The configuration of the secret engine to configure.
            """

            if self.check_mode:
                return None

            path: str = self.params['engine_mount_point']

            try:
                self.client.sys.tune_mount_configuration(
                    path=path,
                    **config)
            except hvac.exceptions.Forbidden:
                self.handle_error(
                    VaultModuleError(
                        message=f"Forbidden: Permission Denied to path '{path}'",
                        exception=traceback.format_exc()
                    )
                )
            except Exception:
                self.handle_error(
                    VaultModuleError(
                        message=f"Error configuring mount '{path}'",
                        exception=traceback.format_exc()
                    )
                )
