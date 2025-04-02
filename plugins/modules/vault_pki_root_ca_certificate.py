#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r"""
module: vault_pki_root_ca_certificate
version_added: 1.2.0
author:
  - Jim Tarpley (@trippsc2)
short_description: Configures a PKI root CA certificate in HashiCorp Vault
description:
  - >-
    Ensures a L(PKI secret engine root CA certificate,https://hvac.readthedocs.io/en/stable/usage/secrets_engines/pki.html#generate-root)
    is configured in HashiCorp Vault.
extends_documentation_fragment:
  - trippsc2.hashi_vault.auth
  - trippsc2.hashi_vault.connection
  - trippsc2.hashi_vault.action_group
  - trippsc2.hashi_vault.check_mode
  - trippsc2.hashi_vault.engine_mount
  - trippsc2.hashi_vault.requirements
options:
  state:
    type: str
    required: false
    default: present
    choices:
      - present
      - absent
    description:
      - The expected state of the root CA certificate.
  common_name:
    type: str
    required: false
    description:
      - The common name for the root CA certificate.
      - Required when O(state=present).
  export_private_key:
    type: bool
    required: false
    default: false
    description:
      - Whether to export the private key when creating the root certificate.
      - If set to V(true), the private key will be returned in the response without no_log masking.
  alt_names:
    type: list
    required: false
    elements: str
    description:
      - The list of Subject Alternative Names (SANs) to include in the certificate.
      - These can be host names (DNS names) or email addresses.
      - If not provided, no SANs will be included.
  ip_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of IP Address Subject Alternative Names (SANs).
      - These can be IPv4 or IPv6 addresses.
      - If not provided, no IP SANs will be included.
  uri_sans:
    type: list
    required: false
    elements: str
    description:
      - The list of URI Subject Alternative Names.
      - If not provided, no URI SANs will be included.
  other_sans:
    type: list
    required: false
    elements: dict
    description:
      - The list of custom OID/UTF8-string SANs.
      - If not provided, no custom SANs will be included.
    suboptions:
      oid:
        type: str
        required: true
        description:
          - The OID for the custom SAN.
      type:
        type: str
        required: false
        default: utf8
        choices:
          - utf8
        description:
          - The type of the custom SAN.
      value:
        type: str
        required: true
        description:
          - The value of the custom SAN.
  ttl:
    type: str
    required: false
    description:
      - The expiration duration of the root certificate to be generated.
      - This value can be provided as a duration string, such as V(72h), or as an number of seconds.
      - This must be less than or equal to the value of the C(max_ttl) parameter of the PKI secrets engine.
      - If not provided, the value of the C(default_lease_ttl) parameter of the PKI secrets engine will be used.
  format:
    type: str
    required: false
    choices:
      - pem
      - der
      - pem_bundle
    description:
      - The format of the returned CA certificate data.
      - If V(pem_bundle), the certificate field will contain the private key (if exported) and
        certificate concatenated.
      - If not provided, the certificate will be returned in PEM format.
  private_key_format:
    type: str
    choices:
      - der
      - pkcs8
    description:
      - The format for marshaling the private key.
      - If set to V(der) and O(format=pem) or O(format=pem_bundle), the private key will be returned in PEM-encoded DER format.
      - If set to V(der) and O(format=der), the private key will be returned in base64-encoded DER format.
      - If set to V(pkcs8), the private key will be returned in PEM-encoded PKCS8 format.
      - If not provided, the private key will be marshaled as if the V(der) value was provided.
  key_type:
    type: str
    required: false
    choices:
      - rsa
      - ec
    description:
      - The desired private key algorithm type.
      - If not provided, the private key will use the RSA algorithm.
  key_bits:
    type: int
    required: false
    choices:
      - 224
      - 256
      - 384
      - 521
      - 2048
      - 3072
      - 4096
      - 8192
    description:
      - The number of bits to use for generated keys.
      - If O(key_type=rsa), the allowed values are V(2048), V(3072), V(4096), and V(8192).
      - If not provided and O(key_type=rsa), this defaults to V(2048) on new roles.
      - If O(key_type=ec), the allowed values are V(224), V(256), V(384), and V(521).
      - If not provided and O(key_type=ec), this defaults to V(256) on new roles.
  max_path_length:
    type: int
    required: false
    description:
      - The maximum path length to encode in the generated certificate.
      - If set to V(-1), no limit is given.
      - If set to V(0), no CA certificates can be signed by this CA.
      - If not provided, the default is V(-1).
  exclude_cn_from_sans:
    type: bool
    required: false
    description:
      - Whether to exclude the common name from the Subject Alternate Names (SANs).
      - If set to V(true), the given O(common_name) will not be added to the list of SANs.
      - If set to V(false), the given O(common_name) will be added to the list of SANs and parsed as a DNS name or email address.
  permitted_dns_domains:
    type: list
    required: false
    elements: str
    description:
      - The list of DNS domains for which certificates are allowed to be issued or signed by this CA certificate.
      - Note that subdomains are allowed, as per L(RFC5280,https://tools.ietf.org/html/rfc5280\#section-4.2.1.10).
      - If not provided, all DNS domains are permitted.
  ou:
    type: list
    required: false
    elements: str
    description:
      - The Organizational Unit (OU) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  organization:
    type: list
    required: false
    elements: str
    description:
      - The Organization (O) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  country:
    type: list
    required: false
    elements: str
    description:
      - The Country (C) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  locality:
    type: list
    required: false
    elements: str
    description:
      - The Locality (L) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  province:
    type: list
    required: false
    elements: str
    description:
      - The Province or State (ST) values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  street_address:
    type: list
    required: false
    elements: str
    description:
      - The Street Address values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  postal_code:
    type: list
    required: false
    elements: str
    description:
      - The Postal Code values to include in the CA certificate.
      - If not provided, this defaults to an empty list on new roles.
  serial_number:
    type: str
    required: false
    description:
      - The serial number of the root CA certificate.
      - If you want more than one, specify alternative names in the alt_names map using OID 2.5.4.5.
      - If not provided, HashiCorp Vault will generate a random serial number for the certificate.
"""

EXAMPLES = r"""
- name: Ensure root CA certificate is configured
  trippsc2.hashi_vault.vault_pki_root_ca_certificate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    common_name: my-root-ca
    state: present

- name: Ensure root CA certificate is not configured
  trippsc2.hashi_vault.vault_pki_root_ca_certificate:
    url: https://vault:8201
    auth_method: userpass
    username: '{{ user }}'
    password: '{{ passwd }}'
    engine_mount_point: pki
    state: absent
"""

RETURN = r"""
certificate:
  description: The root CA certificate.
  type: str
  returned: O(state=present)
private_key:
  description: The private key for the root CA certificate.
  type: str
  returned: |
    changed
    O(state=present)
    O(export_private_key=true)
prev_certificate:
  description: The previous root CA certificate.
  type: str
  returned: |
    changed
    O(state=absent)
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
from ..module_utils._vault_cert import other_sans_to_list_of_str
from ..module_utils._vault_module import VaultModule
from ..module_utils._vault_module_error import VaultModuleError


class VaultPKIRootCACertificateModule(VaultModule):
    """
    Vault PKI Root CA Certificate Module
    """

    ARGSPEC: dict = dict(
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

    DURATION_PARAMS: list[str] = ['ttl']

    LIST_PARAMS_TO_JOIN: list[str] = ['alt_names']

    def __init__(self, *args, **kwargs) -> None:

        argspec: dict = self.ARGSPEC.copy()

        super(VaultPKIRootCACertificateModule, self).__init__(
            *args,
            argument_spec=argspec,
            supports_check_mode=True,
            required_if=[
                ('state', 'present', ['common_name'])
            ],
            **kwargs
        )

    def read_certificate_data(self) -> Optional[str]:
        """
        Read the current root CA certificate data from the Vault server.

        Returns:
            Optional[str]: The root CA certificate data, or None if no certificate exists.
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

        type: str = 'exported' if export_private_key else 'internal'

        extra_params: dict = {}

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

        payload: dict = dict(
            type=type,
            mount_point=engine_mount_point,
            common_name=common_name,
            extra_params=extra_params
        )

        return payload


def ensure_certificate_absent(
        module: VaultPKIRootCACertificateModule,
        certificate_data: Optional[str]) -> dict:
    """
    Ensure that the root CA certificate is absent.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (Optional[str]): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """

    engine_mount_point: str = module.params['engine_mount_point']

    if certificate_data is None:
        return dict(changed=False)

    if not module.check_mode:
        try:
            response: dict = module.client.secrets.pki.delete_root(mount_point=engine_mount_point)
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
        certificate_data: Optional[str]) -> dict:
    """
    Ensure that the root CA certificate is present.

    Args:
        module (VaultPKIRootCACertificateModule): The module object.
        certificate_data (Optional[str]): The current root CA certificate data.

    Returns:
        dict: The result of the operation.
    """

    if certificate_data is not None:
        return dict(changed=False)

    if module.check_mode:
        return dict(changed=True)

    payload: dict = module.build_request_payload()

    try:
        response: dict = module.client.secrets.pki.generate_root(**payload)
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

    result: dict = dict(
        changed=True,
        certificate=response["data"]["certificate"]
    )

    if "private_key" in response["data"]:
        result['private_key'] = response["data"]["private_key"]

    return result


def run_module() -> None:

    module = VaultPKIRootCACertificateModule()

    if not HAS_HVAC:
        module.fail_json(
            msg=missing_required_lib('hvac'),
            exception=HVAC_IMPORT_ERROR)

    state: str = module.params['state']

    module.initialize_client()

    certificate_data: Optional[str] = module.read_certificate_data()

    if state == 'present':
        result = ensure_certificate_present(module, certificate_data)
    else:
        result = ensure_certificate_absent(module, certificate_data)

    module.exit_json(**result)


def main() -> None:
    run_module()


if __name__ == '__main__':
    main()
