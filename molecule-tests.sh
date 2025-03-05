#! /bin/bash

set -e

molecule test -s vault_database_secret_engine
molecule test -s vault_database_static_role
molecule test -s vault_init
molecule test -s vault_kv1_secret_engine
molecule test -s vault_kv2_secret_engine
molecule test -s vault_pki_generate_intermediate_csr
molecule test -s vault_pki_role
molecule test -s vault_pki_root_ca_certificate
molecule test -s vault_pki_secret_engine
molecule test -s vault_pki_set_signed_intermediate
molecule test -s vault_pki_sign_intermediate
molecule test -s vault_pki_sign_verbatim
molecule test -s vault_unseal
