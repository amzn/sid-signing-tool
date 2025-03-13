# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest

from cryptography.exceptions import InvalidSignature
from helpers import get_cert_data

from sid_signing_tool import api
from sid_signing_tool.cert import SidewalkCertChain
from sid_signing_tool.certstore.mem import MemCertStore
from sid_signing_tool.exceptions import InvalidCSRLength, InvalidEcdsaCSR, InvalidEddsaCSR
from sid_signing_tool.types import CATYPE, CURVE, ELEMENT, STAGE


class TestApi(unittest.TestCase):
    def setUp(self):
        self.mem_store = MemCertStore(get_cert_data())
        self.mem_store.open()

    def tearDown(self):
        self.mem_store.close()

    def test_decode_csr(self):
        csr_smsn = bytes.fromhex("35f59d25e512bb41c136ad759a0f92790beed1a7efbad5ace827051cea482a2a")
        csr_pubk_ed25519 = bytes.fromhex(
            "c06e9dd619cb14a80f2986ac56baa5f987807993eda2541a0efc65cb452f7ec4"
        )
        csr_pubk_p256r1 = bytes.fromhex(
            "bca86f9a0e7a443ebdc2280a304742243985a4b07bb211e98b3901004cfe46785b02d501248e8887a367892e2af2e44cf1b39417a9f1cef96807f1a2f5f91142"
        )
        csr_sig_ed25519 = bytes.fromhex(
            "f27806eaeb34f081379e03b6ef4fdf44d935f9d6d907b9f1852defe14e15bcc9497cfa5ae7cf855b54c812bb690828a7062bedb11710d98cdf01eb610f819703"
        )
        csr_sig_p256r1 = bytes.fromhex(
            "4ec618fba313294ed23541658df5243f9b26193b6012114fedc1b00b2179513ead9dd8ed1c1c5c3a8d4e2f9ca74a5eb3c3ac60542db165d6a3c9cb77c45dad37"
        )

        # CSR contains PUBK only
        (pubk, smsn, sig) = api.decode_csr(csr_pubk_ed25519, 0, CURVE.ED25519)
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, bytes())
        self.assertEqual(sig, bytes())

        (pubk, smsn, sig) = api.decode_csr(csr_pubk_p256r1, 0, CURVE.P256R1)
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, bytes())
        self.assertEqual(sig, bytes())

        # CSR contains PUBK + SN
        (pubk, smsn, sig) = api.decode_csr(csr_pubk_ed25519 + csr_smsn, 32, CURVE.ED25519)
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, bytes())

        (pubk, smsn, sig) = api.decode_csr(csr_pubk_p256r1 + csr_smsn, 32, CURVE.P256R1)
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, bytes())

        # CSR contains PUBK + SN + PUBK
        (pubk, smsn, sig) = api.decode_csr(
            csr_pubk_ed25519 + csr_smsn + csr_sig_ed25519, 32, CURVE.ED25519
        )
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, csr_sig_ed25519)

        (pubk, smsn, sig) = api.decode_csr(
            csr_pubk_p256r1 + csr_smsn + csr_sig_p256r1, 32, CURVE.P256R1
        )
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, csr_sig_p256r1)

        # Invalid length
        with self.assertRaises(InvalidCSRLength):
            api.decode_csr(b"\0" * 16, 0, CURVE.P256R1)

        with self.assertRaises(InvalidCSRLength):
            api.decode_csr(b"\0" * 256, 0, CURVE.P256R1)

        # Invalid signature
        with self.assertRaises(InvalidSignature):
            api.decode_csr(
                csr_pubk_ed25519 + csr_smsn + b"\0" * len(csr_sig_ed25519),
                32,
                CURVE.ED25519,
            )

        with self.assertRaises(InvalidSignature):
            api.decode_csr(
                csr_pubk_p256r1 + csr_smsn + b"\0" * len(csr_sig_p256r1),
                32,
                CURVE.P256R1,
            )

    def test_sign_csr_on_devce_gen(self):
        ed25519_csr = base64.standard_b64decode(
            "wG6d1hnLFKgPKYasVrql+YeAeZPtolQaDvxly0UvfsQ19Z0l5RK7QcE2rXWaD5J5C+7Rp++61azoJwUc6kgqKvJ4BurrNPCBN54Dtu9P30TZNfnW2Qe58YUt7+FOFbzJSXz6WufPhVtUyBK7aQgopwYr7bEXENmM3wHrYQ+BlwM="
        )
        p256r1_csr = base64.standard_b64decode(
            "vKhvmg56RD69wigKMEdCJDmFpLB7shHpizkBAEz+RnhbAtUBJI6Ih6NniS4q8uRM8bOUF6nxzvloB/Gi9fkRQjX1nSXlErtBwTatdZoPknkL7tGn77rVrOgnBRzqSCoqTsYY+6MTKU7SNUFljfUkP5smGTtgEhFP7cGwCyF5UT6tndjtHBxcOo1OL5ynSl6zw6xgVC2xZdajyct3xF2tNw=="
        )
        result = api.sign_csr(
            ed25519_csr=ed25519_csr, p256r1_csr=p256r1_csr, cert_store=self.mem_store
        )

        self.assertEqual(
            result["smsn"],
            bytes.fromhex("35f59d25e512bb41c136ad759a0f92790beed1a7efbad5ace827051cea482a2a"),
        )

        self.assertEqual(
            result["ed25519_chain"],
            base64.standard_b64decode(
                "NfWdJeUSu0HBNq11mg+SeQvu0afvutWs6CcFHOpIKirAbp3WGcsUqA8phqxWuqX5h4B5k+2iVBoO/GXLRS9+xCyGl11n6xD7uVtnb7Ct/Rp/U3wMdv9P3MptQryJp7Ocss1EL40ZY7k5vz5uZhdvIp4oGImIRmXICneC/NtuowbkfIOxB/+4p1UDTYAECyTsVEBR3BRGHvVCf65jkpgHvbbeQOgU2+Hgh6RzfCY/toRu+GvyDxqD8BZEHJgeGoxdgYGfoF8GD9xDeGC9Cp82fTN0uyMmKGygG3TCVphPiFHYTTk7Bc6mhbdhLnaWULUQf5TTNkKW5vGP/Z30f9WCO/KaIR9R4m/hdJBEOI9gjjJ3sRP/7SSbUenW2Qec/eYMTqL+VzHmrVql29Lz1rnkh4saQX+wA747+PoduIlcXVDHf0JArPPN0BVHwAt71dR+poTHo/m/9Gggp7atvdhB6+5s44X16JOEaw2VZc3l1W25iqsuZCm3Zx3WTTUmfjnmGBzG7IPbA+3+rN3mneSPtgGUaHi/74mPhEeC/zuQ2akBp9DWXLLvc/ngSGGgdg8OPDRMQY8v1TaNuoVVOh5rIZ8gssbdWwzdlAPHC2FvtITEHbzGmhrJmuTvF7OOulmdkQKjkVWZHnQP8OAXDIgmVZU6FwE/yIK0nobqcRNArbMjkaWVrGVyPynMCE64JsQfPQ1/DvHYA7nNsN5PMeAHbz2rElwdpICSwSdIAgPHA6fajBAWFHyjLAckPAQZ2yAL2pF8RsXgLutXAlRjrX97HqUcb8JJQOuv3nMQ789l9sVDmKFzYfJRl3i2mqrCfP80yNBgmMNvFuEM"
            ),
        )
        ed25519_chain = SidewalkCertChain.from_raw(result["ed25519_chain"], CURVE.ED25519)
        ed25519_chain.validate()

        p256r1_chain = SidewalkCertChain.from_raw(result["p256r1_chain"], CURVE.P256R1)
        p256r1_chain.validate()

    def test_sign_csr_3p_smsn_generated(self):
        ed25519_csr = base64.standard_b64decode("tvm6WWmB6cXWvzDhQkHhp5J0LSTLksCkVdXjAS4FURM=")
        p256r1_csr = base64.standard_b64decode(
            "HYVgSfiGiqDfmVRXCHxwVfxT8ESBVsByiw9g3KnDpcsDwsqQRDvkQvze0tID+v5GTqpv5qn/tLtfLbNDXAiEtA=="
        )
        result = api.sign_csr(
            ed25519_csr=ed25519_csr,
            p256r1_csr=p256r1_csr,
            cert_store=self.mem_store,
            sn_len=0,
            stage=STAGE.PROD,
            dsn="G1234",
            apid="TEST",
            device_type_id="TEST",
        )

        self.assertEqual(
            result["smsn"],
            bytes.fromhex("20eb3c2b576035195136ad0b91d03903c7aa995a65f998cab0b215bf5328cdc6"),
        )

        self.assertEqual(
            result["ed25519_chain"],
            base64.standard_b64decode(
                "IOs8K1dgNRlRNq0LkdA5A8eqmVpl+ZjKsLIVv1Mozca2+bpZaYHpxda/MOFCQeGnknQtJMuSwKRV1eMBLgVREwbZuvG9pB0LKCdCIvPvAovY/ooJOCYAusrBrEfiKevruMhZzT6hd3zTrjns7DEuu8uLVIVctX8vsRJM4eKcogXkfIOxB/+4p1UDTYAECyTsVEBR3BRGHvVCf65jkpgHvbbeQOgU2+Hgh6RzfCY/toRu+GvyDxqD8BZEHJgeGoxdgYGfoF8GD9xDeGC9Cp82fTN0uyMmKGygG3TCVphPiFHYTTk7Bc6mhbdhLnaWULUQf5TTNkKW5vGP/Z30f9WCO/KaIR9R4m/hdJBEOI9gjjJ3sRP/7SSbUenW2Qec/eYMTqL+VzHmrVql29Lz1rnkh4saQX+wA747+PoduIlcXVDHf0JArPPN0BVHwAt71dR+poTHo/m/9Gggp7atvdhB6+5s44X16JOEaw2VZc3l1W25iqsuZCm3Zx3WTTUmfjnmGBzG7IPbA+3+rN3mneSPtgGUaHi/74mPhEeC/zuQ2akBp9DWXLLvc/ngSGGgdg8OPDRMQY8v1TaNuoVVOh5rIZ8gssbdWwzdlAPHC2FvtITEHbzGmhrJmuTvF7OOulmdkQKjkVWZHnQP8OAXDIgmVZU6FwE/yIK0nobqcRNArbMjkaWVrGVyPynMCE64JsQfPQ1/DvHYA7nNsN5PMeAHbz2rElwdpICSwSdIAgPHA6fajBAWFHyjLAckPAQZ2yAL2pF8RsXgLutXAlRjrX97HqUcb8JJQOuv3nMQ789l9sVDmKFzYfJRl3i2mqrCfP80yNBgmMNvFuEM"
            ),
        )
        ed25519_chain = SidewalkCertChain.from_raw(result["ed25519_chain"], CURVE.ED25519)
        ed25519_chain.validate()

        p256r1_chain = SidewalkCertChain.from_raw(result["p256r1_chain"], CURVE.P256R1)
        p256r1_chain.validate()

    def test_sign_encoded_csr(self):
        ed25519_csr = "wG6d1hnLFKgPKYasVrql+YeAeZPtolQaDvxly0UvfsQ19Z0l5RK7QcE2rXWaD5J5C+7Rp++61azoJwUc6kgqKvJ4BurrNPCBN54Dtu9P30TZNfnW2Qe58YUt7+FOFbzJSXz6WufPhVtUyBK7aQgopwYr7bEXENmM3wHrYQ+BlwM="
        p256r1_csr = "vKhvmg56RD69wigKMEdCJDmFpLB7shHpizkBAEz+RnhbAtUBJI6Ih6NniS4q8uRM8bOUF6nxzvloB/Gi9fkRQjX1nSXlErtBwTatdZoPknkL7tGn77rVrOgnBRzqSCoqTsYY+6MTKU7SNUFljfUkP5smGTtgEhFP7cGwCyF5UT6tndjtHBxcOo1OL5ynSl6zw6xgVC2xZdajyct3xF2tNw=="
        result = api.sign_encoded_csr(
            ed25519_csr=ed25519_csr, p256r1_csr=p256r1_csr, cert_store=self.mem_store
        )

        self.assertEqual(
            result["smsn"],
            "35f59d25e512bb41c136ad759a0f92790beed1a7efbad5ace827051cea482a2a",
        )

        self.assertEqual(
            result["ed25519_chain"],
            "NfWdJeUSu0HBNq11mg+SeQvu0afvutWs6CcFHOpIKirAbp3WGcsUqA8phqxWuqX5h4B5k+2iVBoO/GXLRS9+xCyGl11n6xD7uVtnb7Ct/Rp/U3wMdv9P3MptQryJp7Ocss1EL40ZY7k5vz5uZhdvIp4oGImIRmXICneC/NtuowbkfIOxB/+4p1UDTYAECyTsVEBR3BRGHvVCf65jkpgHvbbeQOgU2+Hgh6RzfCY/toRu+GvyDxqD8BZEHJgeGoxdgYGfoF8GD9xDeGC9Cp82fTN0uyMmKGygG3TCVphPiFHYTTk7Bc6mhbdhLnaWULUQf5TTNkKW5vGP/Z30f9WCO/KaIR9R4m/hdJBEOI9gjjJ3sRP/7SSbUenW2Qec/eYMTqL+VzHmrVql29Lz1rnkh4saQX+wA747+PoduIlcXVDHf0JArPPN0BVHwAt71dR+poTHo/m/9Gggp7atvdhB6+5s44X16JOEaw2VZc3l1W25iqsuZCm3Zx3WTTUmfjnmGBzG7IPbA+3+rN3mneSPtgGUaHi/74mPhEeC/zuQ2akBp9DWXLLvc/ngSGGgdg8OPDRMQY8v1TaNuoVVOh5rIZ8gssbdWwzdlAPHC2FvtITEHbzGmhrJmuTvF7OOulmdkQKjkVWZHnQP8OAXDIgmVZU6FwE/yIK0nobqcRNArbMjkaWVrGVyPynMCE64JsQfPQ1/DvHYA7nNsN5PMeAHbz2rElwdpICSwSdIAgPHA6fajBAWFHyjLAckPAQZ2yAL2pF8RsXgLutXAlRjrX97HqUcb8JJQOuv3nMQ789l9sVDmKFzYfJRl3i2mqrCfP80yNBgmMNvFuEM",
        )
        ed25519_chain = SidewalkCertChain.from_raw(result["ed25519_chain"], CURVE.ED25519)
        ed25519_chain.validate()

        p256r1_chain = SidewalkCertChain.from_raw(result["p256r1_chain"], CURVE.P256R1)
        p256r1_chain.validate()

    def test_sign_csr_with_invalid_ones(self):
        ed25519_csr = base64.standard_b64decode(
            "wG6d1hnLFKgPKYasVrql+YeAeZPtolQaDvxly0UvfsQ19Z0l5RK7QcE2rXWaD5J5C+7Rp++61azoJwUc6kgqKvJ4BurrNPCBN54Dtu9P30TZNfnW2Qe58YUt7+FOFbzJSXz6WufPhVtUyBK7aQgopwYr7bEXENmM3wHrYQ+BlwM="
        )
        p256r1_csr = base64.standard_b64decode(
            "vKhvmg56RD69wigKMEdCJDmFpLB7shHpizkBAEz+RnhbAtUBJI6Ih6NniS4q8uRM8bOUF6nxzvloB/Gi9fkRQjX1nSXlErtBwTatdZoPknkL7tGn77rVrOgnBRzqSCoqTsYY+6MTKU7SNUFljfUkP5smGTtgEhFP7cGwCyF5UT6tndjtHBxcOo1OL5ynSl6zw6xgVC2xZdajyct3xF2tNw=="
        )

        invalid_ed25519_csr = b"z" + ed25519_csr[1:]
        with self.assertRaises(InvalidEddsaCSR):
            api.sign_csr(
                ed25519_csr=invalid_ed25519_csr,
                p256r1_csr=p256r1_csr,
                cert_store=self.mem_store,
            )

        invalid_p256r1_csr = b"z" + p256r1_csr[1:]
        with self.assertRaises(InvalidEcdsaCSR):
            api.sign_csr(
                ed25519_csr=ed25519_csr,
                p256r1_csr=invalid_p256r1_csr,
                cert_store=self.mem_store,
            )

        with self.assertRaises(ValueError):
            api.sign_csr(
                ed25519_csr=None,
                p256r1_csr=invalid_p256r1_csr,
                cert_store=self.mem_store,
            )
        with self.assertRaises(ValueError):
            api.sign_csr(ed25519_csr=ed25519_csr, p256r1_csr=None, cert_store=self.mem_store)

    def test_sign_encoded_csr_with_invalid_ones(self):
        ed25519_csr = "wG6d1hnLFKgPKYasVrql+YeAeZPtolQaDvxly0UvfsQ19Z0l5RK7QcE2rXWaD5J5C+7Rp++61azoJwUc6kgqKvJ4BurrNPCBN54Dtu9P30TZNfnW2Qe58YUt7+FOFbzJSXz6WufPhVtUyBK7aQgopwYr7bEXENmM3wHrYQ+BlwM="
        invalid_ed25519_csr = "wG6d1hnLFKgPKYasVrql+YeAeZPtolQaDvxly0UvfsQ19Z0l5RK7QcE2rXWaD5J5C+7Rp++61azoJwUc6kgqKvJ4BurrNPCBN54Dtu9P30TZNfnW2Qe58YUt7+FOFbzJSXz6WufPhVtUyBK7aQgopwYr7bEXENmM3wHrYQ+BlwM"
        invalid_p256r1_csr = "vKhvmg56RD69wigKMEdCJDmFpLB7shHpizkBAEz+RnhbAtUBJI6Ih6NniS4q8uRM8bOUF6nxzvloB/Gi9fkRQjX1nSXlErtBwTatdZoPknkL7tGn77rVrOgnBRzqSCoqTsYY+6MTKU7SNUFljfUkP5smGTtgEhFP7cGwCyF5UT6tndjtHBxcOo1OL5ynSl6zw6xgVC2xZdajyct3xF2tNw="

        with self.assertRaises(ValueError):
            api.sign_encoded_csr(
                ed25519_csr=invalid_ed25519_csr,
                p256r1_csr=invalid_p256r1_csr,
                cert_store=self.mem_store,
            )

        with self.assertRaises(ValueError):
            api.sign_encoded_csr(
                ed25519_csr=ed25519_csr,
                p256r1_csr=invalid_p256r1_csr,
                cert_store=self.mem_store,
            )


class TestApiConstant(unittest.TestCase):
    def test_curve_constant(self):
        self.assertEqual(CURVE.ED25519, "ed25519")
        self.assertEqual(CURVE.P256R1, "p256r1")

    def test_stage_constant(self):
        self.assertEqual(STAGE.PROD, "prod")
        self.assertEqual(STAGE.TEST, "test")
        self.assertEqual(STAGE.PREPROD, "preprod")

    def test_element_constant(self):
        self.assertEqual(ELEMENT.PRIV, "private")
        self.assertEqual(ELEMENT.PUBK, "pubkey")
        self.assertEqual(ELEMENT.SIGNATURE, "signature")
        self.assertEqual(ELEMENT.SERIAL, "serial")

    def test_catype_constant(self):
        self.assertEqual(CATYPE.AMZN, "amzn")
        self.assertEqual(CATYPE.SIDEWALK, "sidewalk")
        self.assertEqual(CATYPE.MAN, "man")
        self.assertEqual(CATYPE.PROD, "prod")
        self.assertEqual(CATYPE.DAK, "dak")
        self.assertEqual(CATYPE.DEVICE, "device")
        self.assertEqual(CATYPE.MODEL, "model")
