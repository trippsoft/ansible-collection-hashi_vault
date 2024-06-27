# -*- coding: utf-8 -*-

# Copyright: (c) 2021, Brian Scholer (@briantist)
# GNU General Public License v3.0+ (see LICENSES/GPL-3.0-or-later.txt or https://www.gnu.org/licenses/gpl-3.0.txt)
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r"""
    options:
      auth_method:
        type: str
        default: token
        choices:
          - token
          - userpass
          - ldap
          - approle
          - aws_iam
          - azure
          - jwt
          - cert
          - none
        description:
          - Authentication method to be used.
      mount_point:
        type: str
        description:
          - Vault mount point.
          - If not specified, the default mount point for a given auth method is used.
          - Does not apply to token authentication.
      token:
        type: str
        description:
          - Vault token. Token may be specified explicitly, through the listed [env] vars, and also through the C(VAULT_TOKEN) env var.
          - If no token is supplied, explicitly or through env, then the plugin will check for a token file, as determined by I(token_path) and I(token_file).
          - The order of token loading (first found wins) is C(token param -> ansible var -> ANSIBLE_HASHI_VAULT_TOKEN -> VAULT_TOKEN -> token file).
      token_path:
        type: str
        description:
          - If no token is specified, will try to read the I(token_file) from this path.
      token_file:
        type: str
        default: '.vault-token'
        description:
          - If no token is specified, will try to read the token from this file in I(token_path).
      token_validate:
        type: bool
        default: false
        description:
          - For token auth, will perform a C(lookup-self) operation to determine the token's validity before using it.
          - Disable if your token does not have the C(lookup-self) capability.
      username:
        type: str
        description:
          - Authentication user name.
      password:
        type: str
        description:
          - Authentication password.
      role_id:
        type: str
        description:
          - Vault Role ID or name. Used in C(approle), C(aws_iam), C(azure) and C(cert) auth methods.
          - For C(cert) auth, if no I(role_id) is supplied, the default behavior is to try all certificate roles and return any one that matches.
          - For C(azure) auth, I(role_id) is required.
      secret_id:
        type: str
        description:
          - Secret ID to be used for Vault AppRole authentication.
      jwt:
        type: str
        description:
          - The JSON Web Token (JWT) to use for JWT authentication to Vault.
      aws_profile:
        type: str
        aliases: [ boto_profile ]
        description:
          - The AWS profile
      aws_access_key:
        type: str
        aliases: [ aws_access_key_id ]
        description:
          - The AWS access key to use.
      aws_secret_key:
        type: str
        aliases: [ aws_secret_access_key ]
        description:
          - The AWS secret key that corresponds to the access key.
      aws_security_token:
        type: str
        description:
          - The AWS security token if using temporary access and secret keys.
      region:
        type: str
        description:
          - The AWS region for which to create the connection.
      aws_iam_server_id:
        type: str
        required: False
        description:
          - If specified, sets the value to use for the C(X-Vault-AWS-IAM-Server-ID) header as part of C(GetCallerIdentity) request.
      azure_tenant_id:
        type: str
        required: False
        description:
          - The Azure Active Directory Tenant ID (also known as the Directory ID) of the service principal. Should be a UUID.
          - >-
            Required when using a service principal to authenticate to Vault,
            e.g. required when both I(azure_client_id) and I(azure_client_secret) are specified.
          - Optional when using managed identity to authenticate to Vault.
      azure_client_id:
        type: str
        required: False
        description:
          - The client ID (also known as application ID) of the Azure AD service principal or managed identity. Should be a UUID.
          - If not specified, will use the system assigned managed identity.
      azure_client_secret:
        type: str
        required: False
        description:
          - The client secret of the Azure AD service principal.
      azure_resource:
        type: str
        required: False
        default: https://management.azure.com/
        description:
          - The resource URL for the application registered in Azure Active Directory. Usually should not be changed from the default.
      cert_auth_public_key:
        type: path
        description:
          - For C(cert) auth, path to the certificate file to authenticate with, in PEM format.
      cert_auth_private_key:
        type: path
        description:
          - For C(cert) auth, path to the private key file to authenticate with, in PEM format.
    """

    PLUGINS = r"""
    options:
      auth_method:
        env:
          - name: ANSIBLE_HASHI_VAULT_AUTH_METHOD
        ini:
          - section: hashi_vault_collection
            key: auth_method
        vars:
          - name: ansible_hashi_vault_auth_method
      mount_point:
        env:
          - name: ANSIBLE_HASHI_VAULT_MOUNT_POINT
        ini:
          - section: hashi_vault_collection
            key: mount_point
        vars:
          - name: ansible_hashi_vault_mount_point
      token:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN
        vars:
          - name: ansible_hashi_vault_token
      token_path:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_PATH
        ini:
          - section: hashi_vault_collection
            key: token_path
        vars:
          - name: ansible_hashi_vault_token_path
      token_file:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_FILE
        ini:
          - section: hashi_vault_collection
            key: token_file
        vars:
          - name: ansible_hashi_vault_token_file
      token_validate:
        env:
          - name: ANSIBLE_HASHI_VAULT_TOKEN_VALIDATE
        ini:
          - section: hashi_vault_collection
            key: token_validate
        vars:
          - name: ansible_hashi_vault_token_validate
      username:
        env:
          - name: ANSIBLE_HASHI_VAULT_USERNAME
        vars:
          - name: ansible_hashi_vault_username
      password:
        env:
          - name: ANSIBLE_HASHI_VAULT_PASSWORD
        vars:
          - name: ansible_hashi_vault_password
      role_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_ROLE_ID
        ini:
          - section: hashi_vault_collection
            key: role_id
        vars:
          - name: ansible_hashi_vault_role_id
      secret_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_SECRET_ID
        vars:
          - name: ansible_hashi_vault_secret_id
      jwt:
        env:
          - name: ANSIBLE_HASHI_VAULT_JWT
      aws_profile:
        env:
          - name: AWS_DEFAULT_PROFILE
          - name: AWS_PROFILE
      aws_access_key:
        env:
          - name: EC2_ACCESS_KEY
          - name: AWS_ACCESS_KEY
          - name: AWS_ACCESS_KEY_ID
      aws_secret_key:
        env:
          - name: EC2_SECRET_KEY
          - name: AWS_SECRET_KEY
          - name: AWS_SECRET_ACCESS_KEY
      aws_security_token:
        env:
          - name: EC2_SECURITY_TOKEN
          - name: AWS_SESSION_TOKEN
          - name: AWS_SECURITY_TOKEN
      region:
        env:
          - name: EC2_REGION
          - name: AWS_REGION
      aws_iam_server_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AWS_IAM_SERVER_ID
        ini:
          - section: hashi_vault_collection
            key: aws_iam_server_id
      azure_tenant_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_TENANT_ID
        ini:
          - section: hashi_vault_collection
            key: azure_tenant_id
        vars:
          - name: ansible_hashi_vault_azure_tenant_id
      azure_client_id:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_CLIENT_ID
        ini:
          - section: hashi_vault_collection
            key: azure_client_id
        vars:
          - name: ansible_hashi_vault_azure_client_id
      azure_client_secret:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_CLIENT_SECRET
        vars:
          - name: ansible_hashi_vault_azure_client_secret
      azure_resource:
        env:
          - name: ANSIBLE_HASHI_VAULT_AZURE_RESOURCE
        ini:
          - section: hashi_vault_collection
            key: azure_resource
        vars:
          - name: ansible_hashi_vault_azure_resource
      cert_auth_public_key:
        env:
          - name: ANSIBLE_HASHI_VAULT_CERT_AUTH_PUBLIC_KEY
        vars:
          - name: ansible_hashi_vault_cert_auth_public_key
        ini:
          - section: hashi_vault_collection
            key: cert_auth_public_key
      cert_auth_private_key:
        env:
          - name: ANSIBLE_HASHI_VAULT_CERT_AUTH_PRIVATE_KEY
        vars:
          - name: ansible_hashi_vault_cert_auth_private_key
        ini:
          - section: hashi_vault_collection
            key: cert_auth_private_key
    """
