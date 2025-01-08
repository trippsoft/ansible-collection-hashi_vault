#! /bin/bash

cd ./roles/signed_certificate

aar-doc . markdown

cd ../testing

aar-doc . markdown

cd ../testing_ca

aar-doc . markdown
