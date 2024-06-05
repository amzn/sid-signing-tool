# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import binascii
import sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric import ed25519

with open(sys.argv[1], "rb") as pem:
    private_key = serialization.load_pem_private_key(pem.read(), None)
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        priv = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption())
    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        priv = private_key.private_numbers().private_value.to_bytes(32, 'big')
    print(str(binascii.hexlify(priv), 'ascii'))
