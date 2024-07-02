# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)

from sid_signing_tool.types import CURVE


def verify_with_sig_ed25519(public_key, signature, data):
    pubk = ed25519.Ed25519PublicKey.from_public_bytes(public_key)
    pubk.verify(signature=signature, data=data)


def verify_with_sig_p256r1(public_key, signature, data):
    pubk = ec.EllipticCurvePublicNumbers(
        x=int.from_bytes(public_key[:32], "big"),
        y=int.from_bytes(public_key[32:], "big"),
        curve=ec.SECP256R1(),
    ).public_key()

    signature = encode_dss_signature(
        r=int.from_bytes(signature[:32], "big"), s=int.from_bytes(signature[32:], "big")
    )

    pubk.verify(signature=signature, data=data, signature_algorithm=ec.ECDSA(hashes.SHA256()))


def sign_ed25519(ed25519_priv, data):
    private_key = ed25519.Ed25519PrivateKey.from_private_bytes(ed25519_priv)
    signature = private_key.sign(data)
    return signature


def sign_p256r1(p256r1_priv, data):
    private_key = ec.derive_private_key(int.from_bytes(p256r1_priv, "big"), ec.SECP256R1())
    (r, s) = decode_dss_signature(private_key.sign(data, ec.ECDSA(hashes.SHA256())))
    signature = r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")
    return signature


def load_private_key_from_pem(data, curve):
    if curve == CURVE.ED25519:
        private_key = serialization.load_pem_private_key(data=data, password=None)
        pubk = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
        )
        priv = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )

    elif curve == CURVE.P256R1:
        private_key = serialization.load_pem_private_key(data=data, password=None)
        public_numbers = private_key.public_key().public_numbers()
        pubk = public_numbers.x.to_bytes(32, "big") + public_numbers.y.to_bytes(32, "big")
        private_number = private_key.private_numbers()
        priv = private_number.private_value.to_bytes(32, "big")

    else:
        raise ValueError("unsupported curve")

    return (priv, pubk)
