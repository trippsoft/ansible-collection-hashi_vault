#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DEFAULT_TTL = 2764800

import traceback
import hvac
from hvac.exceptions import InvalidRequest, Forbidden


from ansible_collections.community.hashi_vault.plugins.module_utils._hashi_vault_module import HashiVaultModule


def get_secret_engine_argspec() -> dict:
    return dict(
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


def get_mount_backend_type(module:HashiVaultModule, client:hvac.Client, mount_path:str) -> str | Exception | None:
    """
    Get the backend type of a secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_path (str): The path of the secret engine to get the backend type of.
    
    Returns:
        str: The backend type of the secret engine at the given path.
    """

    try:
        mounted_engines = client.sys.list_mounted_secrets_engines().get('data', {})
    except Forbidden as e:
        module.fail_json(msg="Forbidden: Permission Denied to list mounted engines", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error listing mounted engines", exception=traceback.format_exc())
        return e
    
    mount_data = mounted_engines.get(mount_path + '/', {})

    mount_type = mount_data.get('type', None)

    if mount_type == 'kv':
        version = mount_data.get('options', {}).get('version', "0")

        match version:
            case "1"|1:
                return 'kv-v1'
            case "2"|2:
                return 'kv-v2'
            case _:
                return None
    
    return mount_type


def format_mount_config_data(config_data:dict) -> dict:
    """
    Format the configuration data of a secret engine.

    Args:
        config_data (dict): The configuration data to format.
    
    Returns:
        dict: The formatted configuration data.
    """

    formatted_config_data:dict = {}

    for k, v in config_data.items():
        match k:
            case 'options':
                pass
            case _:
                formatted_config_data[k] = v
    
    return formatted_config_data


def get_formatted_mount_config(module:HashiVaultModule, client:hvac.Client, mount_path:str) -> dict | Exception | None:
    """
    Read the configuration of a secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_path (str): The path of the secret engine to read.
    
    Returns:
        dict: The configuration of the secret engine at the given path.
    """

    try:
        config:dict = client.sys.read_mount_configuration(path=mount_path)
    except InvalidRequest:
        return None
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_path}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error reading mount configuration '{mount_path}'", exception=traceback.format_exc())
        return e

    config_data:dict = config.get('data', {})

    config_data = format_mount_config_data(config_data)

    return config_data


def compare_mount_config(previous_config: dict, desired_config: dict) -> dict:
    """
    Compare the configuration of a secret engine.

    Args:
        previous_config (dict): The previous configuration of the secret engine.
        desired_config (dict): The desired configuration of the secret engine.

    Returns:
        dict: The differences between the previous and desired configurations of the secret engine.
    """

    differences:dict = {}

    for k, v in desired_config.items():
        if k not in previous_config:
            match k:
                case 'description':
                    if v != '':
                        differences[k] = v
                case 'default_lease_ttl'|'max_lease_ttl':
                    if v != DEFAULT_TTL:
                        differences[k] = v
                case 'audit_non_hmac_request_keys'|'audit_non_hmac_response_keys'|'passthrough_request_headers':
                    if v != []:
                        differences[k] = v
                case 'listing_visibility':
                    if v != 'normal':
                        differences[k] = v
                case _:
                    differences[k] = v
        else:
            match k:
                case 'audit_non_hmac_request_keys'|'audit_non_hmac_response_keys'|'passthrough_request_headers':
                    if set(v) != set(previous_config[k]):
                        differences[k] = v
                case _:
                    if v != previous_config[k]:
                        differences[k] = v

    return differences


def disable_mount(module:HashiVaultModule, client:hvac.Client, mount_path:str) -> None | Exception:
    """
    Disable a secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_path (str): The path of the secret engine to disable.
    """

    if module.check_mode:
        return None

    try:
        client.sys.disable_secrets_engine(path=mount_path)
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_path}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error disabling mount '{mount_path}'", exception=traceback.format_exc())
        return e


def enable_mount(
        module:HashiVaultModule,
        client:hvac.Client,
        backend_type:str,
        mount_path:str,
        description:str | None,
        config:dict) -> None | Exception:
    """
    Enable a secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        backend_type (str): The type of secret engine to enable.
        mount_path (str): The path of the secret engine to enable.
        description (str): The description of the secret engine to enable.
        config (dict): The configuration of the secret engine to enable.
    """

    if module.check_mode:
        return None

    try:
        if description is None:
            client.sys.enable_secrets_engine(
                path=mount_path,
                backend_type=backend_type,
                config=config)
        else:
            client.sys.enable_secrets_engine(
                path=mount_path,
                backend_type=backend_type,
                description=description,
                config=config)
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_path}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error enabling mount '{mount_path}'", exception=traceback.format_exc())
        return e


def configure_mount(
        module:HashiVaultModule,
        client:hvac.Client,
        mount_path:str,
        config:dict) -> None | Exception:
    """
    Configure a secret engine at a given path.

    Args:
        module (HashiVaultModule): The module using this function.
        client (Client): The Vault client to use.
        mount_path (str): The path of the secret engine to configure.
        config (dict): The configuration of the secret engine to configure.
    """

    if module.check_mode:
        return None

    try:
        client.sys.tune_mount_configuration(
            path=mount_path,
            **config)
    except Forbidden as e:
        module.fail_json(msg=f"Forbidden: Permission Denied to path '{mount_path}'", exception=traceback.format_exc())
        return e
    except Exception as e:
        module.fail_json(msg=f"Error configuring mount '{mount_path}'", exception=traceback.format_exc())
        return e
