# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest

from cryptography.exceptions import InvalidSignature
from helpers import load_dummy_chains

from sid_signing_tool.cert import SidewalkCert, SidewalkCertChain
from sid_signing_tool.types import CATYPE, CURVE


class TestSidewalkCert(unittest.TestCase):
    def setUp(self):
        self.cert_amzn_ed25519 = SidewalkCert(
            type=CATYPE.AMZN,
            curve=CURVE.ED25519,
            serial=bytes.fromhex("01800003"),
            pubk=bytes.fromhex("3b277fd4832193e80d71744dd0bd3cea93825774a170e5d973da543e02bef2de"),
            signature=bytes.fromhex(
                "6abace4a516ffa5b0d6c2e2b8199f6dccb4804cffb610989c2643e15746ea7a4e4b9b835869cf4e09ff4f5dc60f148999a7b47894af519f913385318a9107e03"
            ),
        )
        self.cert_sidewalk_ed22219 = SidewalkCert(
            type=CATYPE.SIDEWALK,
            curve=CURVE.ED25519,
            serial=bytes.fromhex("75000003"),
            pubk=bytes.fromhex("1b3fa0141797fd934df152709ec35f8338f899ed4781525d528e16f64bf1f5ca"),
            signature=bytes.fromhex(
                "f68c75a40b73a3fdb7414e1d7ec818ce0b9df21e540afe5d461eb1168963cf9c4e37e0b4719d6930afc1070f8a22789c42f1f908c6441f8fe807854efd67ea00"
            ),
        )
        self.cert_amzn_p256r1 = SidewalkCert(
            type=CATYPE.AMZN,
            curve=CURVE.P256R1,
            serial=bytes.fromhex("01800002"),
            pubk=bytes.fromhex(
                "050720a34a9ff9587738021b328ccbca0ac65088a82223c102c237d705a499758e3362c4653b7142e36f07d5ab6b1428450994f406ab792cf5c3dfc6cc481faf"
            ),
            signature=bytes.fromhex(
                "0142623fc5ea8847577aa7f6998309e729280e9c24bdefdc5107cfa63cc542541fbf08c1c2224300d2a438aa0d4f76d41b3fbf7ffa724c4fb131174850167507"
            ),
        )
        self.cert_sidewalk_p256r1 = SidewalkCert(
            type=CATYPE.SIDEWALK,
            curve=CURVE.P256R1,
            serial=bytes.fromhex("75000002"),
            pubk=bytes.fromhex(
                "cfb0fdf8052e84cc93b902c4b9a42ed04e98c1b406cb37d49d5ce4fdc381f5c7c364a74ba32f1591377ec8132d15f43acf2b6c3583be2ea963df50f9d2063b6f"
            ),
            signature=bytes.fromhex(
                "339e499d0a669b6dd640dbc76b556beb39960e3ce31e970d8ab3dbcd7c8194a121917e31ca56923279b852b557b4031a009fdcb02e073d32abddd6b376f12487"
            ),
        )

    def test_create_certificate_with_invalid_length(self):
        with self.assertRaises(ValueError):
            SidewalkCert(
                type=self.cert_amzn_ed25519.type,
                curve=self.cert_amzn_ed25519.curve,
                serial=self.cert_amzn_ed25519.serial,
                pubk=self.cert_amzn_ed25519.pubk + b"\00",
                signature=self.cert_amzn_ed25519.signature + b"\00",
            )

            SidewalkCert(
                type=self.cert_amzn_p256r1.type,
                curve=self.cert_amzn_p256r1.curve,
                serial=self.cert_amzn_p256r1.serial,
                pubk=self.cert_amzn_p256r1.pubk + b"\00",
                signature=self.cert_amzn_p256r1.signature + b"\00",
            )

    def test_verify_another_certificate(self):
        self.cert_amzn_ed25519.verify(self.cert_sidewalk_ed22219)
        with self.assertRaises(InvalidSignature):
            self.cert_sidewalk_ed22219.verify(self.cert_amzn_ed25519)

        self.cert_amzn_p256r1.verify(self.cert_sidewalk_p256r1)
        with self.assertRaises(InvalidSignature):
            self.cert_sidewalk_p256r1.verify(self.cert_amzn_p256r1)

    def test_serial_parser_without_sn_expansion(self):
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex("715c00fa")), 4)
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex("6dc60078")), 4)

    def test_serial_parser_with_sn_expansion(self):
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex("155303b018")), 5)
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex("334404b05212")), 6)


class TestSidewalkCertChain(unittest.TestCase):
    def setUp(self):
        (self.chain_ed25519, self.chain_p256r1) = load_dummy_chains("dummy_certs.json")
        self.base64_chain_ed25519 = "WXFkxKYFigBYGiKyLeUEckM9LkT+2La4NX5EzTEpkDoyp3MLq8+G0NrvNQA6u9IGpmDfYUSRUnBNH2YnlB0SWT7HHKpNsZevyHRKEGXKnaVdM1qk3VyJoYd4rSv3flSOMXC1SoCDtX7BMMqo/5JJLNI+Z8invzcF/xnTs8PKgAbkfIOxB/+4p1UDTYAECyTsVEBR3BRGHvVCf65jkpgHvbbeQOgU2+Hgh6RzfCY/toRu+GvyDxqD8BZEHJgeGoxdgYGfoF8GD9xDeGC9Cp82fTN0uyMmKGygG3TCVphPiFHYTTk7Bc6mhbdhLnaWULUQf5TTNkKW5vGP/Z30f9WCO/KaIR9R4m/hdJBEOI9gjjJ3sRP/7SSbUenW2Qec/eYMTqL+VzHmrVql29Lz1rnkh4saQX+wA747+PoduIlcXVDHf0JArPPN0BVHwAt71dR+poTHo/m/9Gggp7atvdhB6+5s44X16JOEaw2VZc3l1W25iqsuZCm3Zx3WTTUmfjnmGBzG7IPbA+3+rN3mneSPtgGUaHi/74mPhEeC/zuQ2akBp9DWXLLvc/ngSGGgdg8OPDRMQY8v1TaNuoVVOh5rIZ8gssbdWwzdlAPHC2FvtITEHbzGmhrJmuTvF7OOulmdkQKjkVWZHnQP8OAXDIgmVZU6FwE/yIK0nobqcRNArbMjkaWVrGVyPynMCE64JsQfPQ1/DvHYA7nNsN5PMeAHbz2rElwdpICSwSdIAgPHA6fajBAWFHyjLAckPAQZ2yAL2pF8RsXgLutXAlRjrX97HqUcb8JJQOuv3nMQ789l9sVDmKFzYfJRl3i2mqrCfP80yNBgmMNvFuEM"
        self.base64_chain_p256r1 = "FI3tfoo0iI05bKs7gNJ/WN8RGjs98kWtqQgCOJp4zcLJ5gs91lwyvElcRtg5S75O0stMwAo1PlaG9bDzpuuKayRJwqXr42AkRMDAzSTJMV0WUkVIDr1laew1N8pf1G/1AlM/MKuLrRu1JNh4fFTqjqW17hKtVR0JAcVZ68OjrK3ilh96dK0Mh2OlGzpAwMXBmjh7pZGm/RfDl2PT+Bx5PW8HhbuHErh+qvgBxlfu5/KaDah+aWf1ugy8oylasUX34DAFDK+EIXiFJJKy9TJHVkioJ1OPxEx1ZW7+uHdnRNtKgZYeFTuen0FQIx8vFjxyx4WNk7HkSIXik0/ZMUp4+/Rh+LoVtXxtVK2mBEtGc6RIGpM26GjwF43olkcEzvycf82kav3IFnM3hbr4Eww2H19p9PEwy8I1UGkv6w6e5cDBYkqmyndv+z3v6NZEulv3XlOLE3Lt2ULqUeW7ZyVz73VHjxc+w2ID+cEY+YtRNenvk2URYQg/wDZl4SU+dfV4O9q301/fCEbPX6VKBSNio3ILGnwhI7WmYk0QqLWr+IldAqrxscG7yR3vvn+me0oUbHCin3LKPS6xVcGuIA+BkDV5EYRTPe8pf930QVcDUKW6bB7ixM4zva3AtTfaBgbImt2luZcJOAxjFkhZCNW+E3iA3Xn0fw60p9wEYcrCQXWsPvIbtd++r8EAVYWUzZ7Od0mgPTgNyWpurgQ+7qWG5vKQaH2TvdmSynFN+VG+ie5CzbYFBLAGg4JKwSAwfzJBHkLlPGExeEtsIyNqzu+nwa0D2GgfnhkU98vKkAI5WUbFUrPk50xhFsuFXPk+g2AYzd0ljtdo2fBWU5lv9cgpydLuJCg9MzTwQ8o+GaGgx/fPwdNItl3PoZKq9nkNzD6cWb30fRQNrbjwgN73BSk0a3FOAVlY1bmDOfPDZk+Sgy6D1p9AcSh0RbSXLwGmsi91VzuRRV7cgDnR/me8jH+gkVyXZlp0+cbAqCKGSp0jTG0Mga4uKBb6Lf85FxeXFnPOqfeTYmEz3OiYcvYq0qIKbCg2onNYpjY2S5Zcaw9/ujabYGHe0t0ZfonXhKYBX3SdssLTyhH9QP9uTqAq"

    def test_chain_validation(self):
        self.chain_ed25519.validate()
        self.chain_p256r1.validate()

    def test_chain_output(self):
        self.assertEqual(
            self.chain_ed25519.get_raw(),
            base64.standard_b64decode(self.base64_chain_ed25519),
        )
        self.assertEqual(
            self.chain_p256r1.get_raw(),
            base64.standard_b64decode(self.base64_chain_p256r1),
        )

    def test_chain_parse(self):
        chain_from_raw = SidewalkCertChain.from_raw(
            base64.standard_b64decode(self.base64_chain_ed25519), CURVE.ED25519
        )
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_ed25519[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_ed25519[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_ed25519[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_ed25519[i].signature)

        chain_from_raw = SidewalkCertChain.from_raw(
            base64.standard_b64decode(self.base64_chain_p256r1), CURVE.P256R1
        )
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_p256r1[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_p256r1[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_p256r1[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_p256r1[i].signature)

    def test_chain_parse_b64(self):
        chain_from_raw = SidewalkCertChain.from_raw(self.base64_chain_ed25519, CURVE.ED25519)
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_ed25519[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_ed25519[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_ed25519[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_ed25519[i].signature)

        chain_from_raw = SidewalkCertChain.from_raw(self.base64_chain_p256r1, CURVE.P256R1)
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_p256r1[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_p256r1[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_p256r1[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_p256r1[i].signature)

    def test_chain_parse_invalid_b64(self):
        with self.assertRaises(ValueError):
            SidewalkCertChain.from_raw(self.base64_chain_ed25519 + "A", CURVE.ED25519)

        with self.assertRaises(ValueError):
            SidewalkCertChain.from_raw(self.base64_chain_p256r1 + "A", CURVE.P256R1)
