#!/bin/bash
openssl genrsa 4096 > user.key
openssl rsa -in user.key -pubout > user.pub
openssl genrsa 4096 > domain.key
openssl req -new -sha256 -key domain.key -subj "/O=XXXXXX/C=XX" -config openssl-san.cfg >domain.csr
python sign_csr_auto.py -f --public-key user.pub domain.csr > signed.crt
