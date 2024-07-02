# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import os
import unittest

from cryptography.exceptions import InvalidSignature
from helpers import get_test_data_dir

from sid_signing_tool import crypto
from sid_signing_tool.types import CURVE


class TestCrypto(unittest.TestCase):
    def test_load_private_key_from_pem(self):
        with open(os.path.join(get_test_data_dir(), "test_ed25519_priv.pem"), "rb") as f:
            priv, pubk = crypto.load_private_key_from_pem(f.read(), CURVE.ED25519)
            self.assertEqual(
                priv,
                bytes.fromhex("74616516298c6edbf71be8fbcd2221a2f90d4229e67dad8639b7db2e80ff8385"),
            )
            self.assertEqual(
                pubk,
                bytes.fromhex("c8ad677893b0ea74ca44d0d5c875dbb2e61625be4d1cd36759f1e5972fd6edcb"),
            )

        with open(os.path.join(get_test_data_dir(), "test_p256r1_priv.pem"), "rb") as f:
            priv, pubk = crypto.load_private_key_from_pem(f.read(), CURVE.P256R1)
            self.assertEqual(
                priv,
                bytes.fromhex("bc25e2a273d5340f5481615c206d9b5e8aa7ab0f11de0d5810b0dfc7f7e18166"),
            )
            self.assertEqual(
                pubk,
                bytes.fromhex(
                    "3b78d18aeb65c68562345db066f9c564bf68f88fb6289e30fb738167086cae12"
                    "1b580af96806975bd6575ee892fe514e57bdfcd07f56dc1115130a4914262d53"
                ),
            )

    def test_verify_with_sig_ed25519(self):
        data = b"test data"
        pubk = bytes.fromhex("c06e9dd619cb14a80f2986ac56baa5f987807993eda2541a0efc65cb452f7ec4")
        signature = bytes.fromhex(
            "d9c9547d4aae4d283e4683a87186c5ec2b4e0bf3bcbee006487de130c28c55015b3314b858b0ec0054913935493c7052dfc30f619432eb095d42b41ea388e90b"
        )
        crypto.verify_with_sig_ed25519(pubk, signature, data)
        with self.assertRaises(InvalidSignature):
            crypto.verify_with_sig_ed25519(pubk, signature[:-1] + b"0", data)

    def test_verify_with_sig_p256r1(self):
        data = b"test data"
        pubk = bytes.fromhex(
            "bca86f9a0e7a443ebdc2280a304742243985a4b07bb211e98b3901004cfe46785b02d501248e8887a367892e2af2e44cf1b39417a9f1cef96807f1a2f5f91142"
        )
        signature = bytes.fromhex(
            "24632551df098e6100fc859cd8de73b4758dda9d7535d7360235629f3d7b474a5612a5450099a4df7d33b09288caf1e90e7c265b4e2d96f34c3a1ccd8de80e98"
        )
        crypto.verify_with_sig_p256r1(pubk, signature, data)
        with self.assertRaises(InvalidSignature):
            crypto.verify_with_sig_p256r1(pubk, signature[:-1] + b"0", data)

    def test_sign_ed25519(self):
        data = b"test data"
        pubk = bytes.fromhex("ffb8a755034d80040b24ec544051dc14461ef5427fae63929807bdb6de40e814")
        priv = bytes.fromhex("2d7cdb87749e045cfbf943af700330fc278b3cffed92a663f687df7bc098b29a")
        signature = crypto.sign_ed25519(priv, data)
        crypto.verify_with_sig_ed25519(pubk, signature, data)

    def test_sign_p256r1(self):
        data = b"test data"
        pubk = bytes.fromhex(
            "7eaaf801c657eee7f29a0da87e6967f5ba0cbca3295ab145f7e030050caf842178852492b2f532475648a827538fc44c75656efeb8776744db4a81961e153b9e"
        )
        priv = bytes.fromhex("649ecd717a49c13db2b13a755fd20fcf09e1d9e6201f5ba84c61ab5e427a21fa")
        signature = crypto.sign_p256r1(priv, data)
        crypto.verify_with_sig_p256r1(pubk, signature, data)
