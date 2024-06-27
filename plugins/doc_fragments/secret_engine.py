#!/usr/bin/python
# -*- coding: utf-8 -*-

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type


class ModuleDocFragment(object):

    DOCUMENTATION = r"""
    options:
      state:
        type: str
        required: false
        default: present
        choices:
          - present
          - absent
        description:
          - Whether the secret engine should be present or absent.
      replace_different_backend_type:
        type: bool
        required: false
        default: false
        description:
          - Whether to replace the secret engine if it has a different backend type.
      description:
        type: str
        required: false
        description:
          - The description of the secret engine.
      default_lease_ttl:
        type: str
        required: false
        description:
          - The default lease TTL of the secret engine.
      max_lease_ttl:
        type: str
        required: false
        description:
          - The maximum lease TTL of the secret engine.
      audit_non_hmac_request_keys:
        type: list
        required: false
        elements: str
        description:
          - The list of non-HMAC request keys to audit.
      audit_non_hmac_response_keys:
        type: list
        required: false
        elements: str
        description:
          - The list of non-HMAC response keys to audit.
      listing_visibility:
        type: str
        required: false
        choices:
          - normal
          - unauth
          - hidden
        description:
          - The listing visibility of the secret engine.
      passthrough_request_headers:
        type: list
        required: false
        elements: str
        description:
          - The list of request headers to pass through.
    """
