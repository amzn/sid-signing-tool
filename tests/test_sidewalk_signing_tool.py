# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import unittest
import json
import os
from unittest.mock import create_autospec, Mock
from binascii import hexlify

from yubihsm import YubiHsm
from yubihsm.core import AuthSession
from yubihsm.objects import ObjectInfo
from cryptography.exceptions import InvalidSignature

import sidewalk_signing_tool
from sidewalk_signing_tool import CA_TYPE, STAGE, CURVE, SidewalkCert
from sidewalk_signing_tool import SidewalkCert, SidewalkCertChain, SidewalkCertsOnHsm

TEST_PRODUCT = 'RNET_DAK_DUMMY'
TEST_PRODUCT_LEGACY = 'RNET_MODEL_DUMMY'
TEST_DIR = os.path.dirname(__file__)

def load_dummy_chains(file):
    dummy_cert_file = os.path.join(TEST_DIR, file)
    with open(dummy_cert_file, 'r') as f:
        certs = json.loads(f.read())
        chains = {
            'ED25': SidewalkCertChain(),
            'P256R1': SidewalkCertChain()
        }
        type_mapping = {
            'AMZN': CA_TYPE.AMZN,
            'SIDEWALK': CA_TYPE.SIDEWALK,
            'MAN': CA_TYPE.MAN,
            'PROD': CA_TYPE.PROD,
            'MODEL': CA_TYPE.MODEL,
            'DAK': CA_TYPE.DAK,
            'DEVICE' : CA_TYPE.DEVICE
        }

        ca_list = ['AMZN', 'SIDEWALK', 'MAN', 'PROD', 'MODEL', 'DAK', 'DEVICE']

        for curve, chain in certs.items():
            for ca_str in ca_list:
                if ca_str not in chain:
                    continue
                elements = chain[ca_str]
                chains[curve].append(
                    SidewalkCert(type=type_mapping[ca_str],
                                 curve=CURVE.ED25519 if curve == 'ED25' else CURVE.P256R1,
                                 serial=bytes.fromhex(elements['serial']),
                                 pubk=bytes.fromhex(elements['pub']),
                                 signature=bytes.fromhex(elements['signature'])))

        return (chains['ED25'], chains['P256R1'])

def load_hsm_cache(file):
    hsm_content_file = os.path.join(TEST_DIR, file)
    with open(hsm_content_file) as f:
        return json.loads(f.read())

class TestSidewalkCert(unittest.TestCase):
    def setUp(self):
        self.cert_amzn_ed25519 = SidewalkCert(type=CA_TYPE.AMZN,
                                              curve=CURVE.ED25519,
                                              serial=bytes.fromhex("01800003"),
                                              pubk=bytes.fromhex("3b277fd4832193e80d71744dd0bd3cea93825774a170e5d973da543e02bef2de"),
                                              signature=bytes.fromhex("6abace4a516ffa5b0d6c2e2b8199f6dccb4804cffb610989c2643e15746ea7a4e4b9b835869cf4e09ff4f5dc60f148999a7b47894af519f913385318a9107e03"))
        self.cert_sidewalk_ed22219 = SidewalkCert(type=CA_TYPE.SIDEWALK,
                                                  curve=CURVE.ED25519,
                                                  serial=bytes.fromhex("75000003"),
                                                  pubk=bytes.fromhex("1b3fa0141797fd934df152709ec35f8338f899ed4781525d528e16f64bf1f5ca"),
                                                  signature=bytes.fromhex("f68c75a40b73a3fdb7414e1d7ec818ce0b9df21e540afe5d461eb1168963cf9c4e37e0b4719d6930afc1070f8a22789c42f1f908c6441f8fe807854efd67ea00"))
        self.cert_amzn_p256r1 = SidewalkCert(type=CA_TYPE.AMZN,
                                             curve=CURVE.P256R1,
                                             serial=bytes.fromhex("01800002"),
                                             pubk=bytes.fromhex("050720a34a9ff9587738021b328ccbca0ac65088a82223c102c237d705a499758e3362c4653b7142e36f07d5ab6b1428450994f406ab792cf5c3dfc6cc481faf"),
                                             signature=bytes.fromhex("0142623fc5ea8847577aa7f6998309e729280e9c24bdefdc5107cfa63cc542541fbf08c1c2224300d2a438aa0d4f76d41b3fbf7ffa724c4fb131174850167507"))
        self.cert_sidewalk_p256r1 = SidewalkCert(type=CA_TYPE.SIDEWALK,
                                                 curve=CURVE.P256R1,
                                                 serial=bytes.fromhex("75000002"),
                                                 pubk=bytes.fromhex("cfb0fdf8052e84cc93b902c4b9a42ed04e98c1b406cb37d49d5ce4fdc381f5c7c364a74ba32f1591377ec8132d15f43acf2b6c3583be2ea963df50f9d2063b6f"),
                                                 signature=bytes.fromhex("339e499d0a669b6dd640dbc76b556beb39960e3ce31e970d8ab3dbcd7c8194a121917e31ca56923279b852b557b4031a009fdcb02e073d32abddd6b376f12487"))

    def test_create_certificate_with_invalide_length(self):
        with self.assertRaises(ValueError):
            SidewalkCert(type=self.cert_amzn_ed25519.type,
                         curve=self.cert_amzn_ed25519.curve,
                         serial=self.cert_amzn_ed25519.serial,
                         pubk=self.cert_amzn_ed25519.pubk + b'\00',
                         signature=self.cert_amzn_ed25519.signature + b'\00')

            SidewalkCert(type=self.cert_amzn_p256r1.type,
                         curve=self.cert_amzn_p256r1.curve,
                         serial=self.cert_amzn_p256r1.serial,
                         pubk=self.cert_amzn_p256r1.pubk + b'\00',
                         signature=self.cert_amzn_p256r1.signature + b'\00')

    def test_verify_another_certificate(self):
        self.cert_amzn_ed25519.verify(self.cert_sidewalk_ed22219)
        with self.assertRaises(InvalidSignature):
            self.cert_sidewalk_ed22219.verify(self.cert_amzn_ed25519)

        self.cert_amzn_p256r1.verify(self.cert_sidewalk_p256r1)
        with self.assertRaises(InvalidSignature):
            self.cert_sidewalk_p256r1.verify(self.cert_amzn_p256r1)

    def test_serial_parser_without_sn_expansion(self):
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex('715c00fa')), 4)
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex('6dc60078')), 4)

    def test_serial_parser_without_sn_expansion(self):
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex('155303b018')), 5)
        self.assertEqual(SidewalkCert.get_serial_length(bytes.fromhex('334404b05212')), 6)

class TestSidewalkCertChain(unittest.TestCase):

    def setUp(self):
        (self.chain_ed25519, self.chain_p256r1) = load_dummy_chains('dummy_certs.json')
        self.base64_chain_ed25519 = 'WXFkxKYFigBYGiKyLeUEckM9LkT+2La4NX5EzTEpkDoyp3MLq8+G0NrvNQA6u9IGpmDfYUSRUnBNH2YnlB0SWT7HHKpNsZevyHRKEGXKnaVdM1qk3VyJoYd4rSv3flSOMXC1SoCDtX7BMMqo/5JJLNI+Z8invzcF/xnTs8PKgAbkfIOxB/+4p1UDTYAECyTsVEBR3BRGHvVCf65jkpgHvbbeQOgU2+Hgh6RzfCY/toRu+GvyDxqD8BZEHJgeGoxdgYGfoF8GD9xDeGC9Cp82fTN0uyMmKGygG3TCVphPiFHYTTk7Bc6mhbdhLnaWULUQf5TTNkKW5vGP/Z30f9WCO/KaIR9R4m/hdJBEOI9gjjJ3sRP/7SSbUenW2Qec/eYMTqL+VzHmrVql29Lz1rnkh4saQX+wA747+PoduIlcXVDHf0JArPPN0BVHwAt71dR+poTHo/m/9Gggp7atvdhB6+5s44X16JOEaw2VZc3l1W25iqsuZCm3Zx3WTTUmfjnmGBzG7IPbA+3+rN3mneSPtgGUaHi/74mPhEeC/zuQ2akBp9DWXLLvc/ngSGGgdg8OPDRMQY8v1TaNuoVVOh5rIZ8gssbdWwzdlAPHC2FvtITEHbzGmhrJmuTvF7OOulmdkQKjkVWZHnQP8OAXDIgmVZU6FwE/yIK0nobqcRNArbMjkaWVrGVyPynMCE64JsQfPQ1/DvHYA7nNsN5PMeAHbz2rElwdpICSwSdIAgPHA6fajBAWFHyjLAckPAQZ2yAL2pF8RsXgLutXAlRjrX97HqUcb8JJQOuv3nMQ789l9sVDmKFzYfJRl3i2mqrCfP80yNBgmMNvFuEM'
        self.base64_chain_p256r1 = 'FI3tfoo0iI05bKs7gNJ/WN8RGjs98kWtqQgCOJp4zcLJ5gs91lwyvElcRtg5S75O0stMwAo1PlaG9bDzpuuKayRJwqXr42AkRMDAzSTJMV0WUkVIDr1laew1N8pf1G/1AlM/MKuLrRu1JNh4fFTqjqW17hKtVR0JAcVZ68OjrK3ilh96dK0Mh2OlGzpAwMXBmjh7pZGm/RfDl2PT+Bx5PW8HhbuHErh+qvgBxlfu5/KaDah+aWf1ugy8oylasUX34DAFDK+EIXiFJJKy9TJHVkioJ1OPxEx1ZW7+uHdnRNtKgZYeFTuen0FQIx8vFjxyx4WNk7HkSIXik0/ZMUp4+/Rh+LoVtXxtVK2mBEtGc6RIGpM26GjwF43olkcEzvycf82kav3IFnM3hbr4Eww2H19p9PEwy8I1UGkv6w6e5cDBYkqmyndv+z3v6NZEulv3XlOLE3Lt2ULqUeW7ZyVz73VHjxc+w2ID+cEY+YtRNenvk2URYQg/wDZl4SU+dfV4O9q301/fCEbPX6VKBSNio3ILGnwhI7WmYk0QqLWr+IldAqrxscG7yR3vvn+me0oUbHCin3LKPS6xVcGuIA+BkDV5EYRTPe8pf930QVcDUKW6bB7ixM4zva3AtTfaBgbImt2luZcJOAxjFkhZCNW+E3iA3Xn0fw60p9wEYcrCQXWsPvIbtd++r8EAVYWUzZ7Od0mgPTgNyWpurgQ+7qWG5vKQaH2TvdmSynFN+VG+ie5CzbYFBLAGg4JKwSAwfzJBHkLlPGExeEtsIyNqzu+nwa0D2GgfnhkU98vKkAI5WUbFUrPk50xhFsuFXPk+g2AYzd0ljtdo2fBWU5lv9cgpydLuJCg9MzTwQ8o+GaGgx/fPwdNItl3PoZKq9nkNzD6cWb30fRQNrbjwgN73BSk0a3FOAVlY1bmDOfPDZk+Sgy6D1p9AcSh0RbSXLwGmsi91VzuRRV7cgDnR/me8jH+gkVyXZlp0+cbAqCKGSp0jTG0Mga4uKBb6Lf85FxeXFnPOqfeTYmEz3OiYcvYq0qIKbCg2onNYpjY2S5Zcaw9/ujabYGHe0t0ZfonXhKYBX3SdssLTyhH9QP9uTqAq'
        
    def test_chain_validation(self):
        self.chain_ed25519.validate()
        self.chain_p256r1.validate()

    def test_chain_output(self):
        self.assertEqual(self.chain_ed25519.get_raw(),
                         base64.standard_b64decode(self.base64_chain_ed25519))
        self.assertEqual(self.chain_p256r1.get_raw(),
                         base64.standard_b64decode(self.base64_chain_p256r1))

    def test_chain_parse(self):
        chain_from_raw = SidewalkCertChain.from_raw(base64.standard_b64decode(self.base64_chain_ed25519), CURVE.ED25519)
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_ed25519[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_ed25519[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_ed25519[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_ed25519[i].signature)

        chain_from_raw = SidewalkCertChain.from_raw(base64.standard_b64decode(self.base64_chain_p256r1), CURVE.P256R1)
        for i in range(len(chain_from_raw)):
            self.assertEqual(chain_from_raw[i].type, self.chain_p256r1[i].type)
            self.assertEqual(chain_from_raw[i].serial, self.chain_p256r1[i].serial)
            self.assertEqual(chain_from_raw[i].pubk, self.chain_p256r1[i].pubk)
            self.assertEqual(chain_from_raw[i].signature, self.chain_p256r1[i].signature)

class TestSidewalkCertsOnHsm(unittest.TestCase):

    def get_mock_yubihsm_session(self, hsm_content_file):
        hsm_content = load_hsm_cache(hsm_content_file)
        object_list = []
        for k, v in hsm_content.items():
            mock_object = Mock()
            (mock_object.id, mock_object.object_type) = (v["id"], v["type"])
            mock_object.get_info.return_value = ObjectInfo(*v['info'])
            if 'content' in v:
                mock_object.get.return_value = bytes.fromhex(v['content'])
            object_list.append(mock_object)

        mock_session = create_autospec(AuthSession)
        mock_session.list_objects.return_value = object_list
        return mock_session

    def setUp(self):
        self.mock_session = self.get_mock_yubihsm_session('hsm_content.json')
        self.mock_session_legacy = self.get_mock_yubihsm_session('hsm_content_legacy.json')

    def test_init_a_hsm_store(self):
        SidewalkCertsOnHsm(self.mock_session, TEST_PRODUCT)

    def test_init_a_hsm_store_legacy(self):
        SidewalkCertsOnHsm(self.mock_session_legacy, TEST_PRODUCT_LEGACY)

    def test_get_certificate(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains('dummy_certs.json')

        def cert_equal(cert1, cert2, msg=None):
            if (cert1.serial != cert2.serial
                or cert1.pubk != cert2.pubk
                or cert1.signature != cert2.signature):
                    raise self.failureException(msg)
        self.addTypeEqualityFunc(SidewalkCert, cert_equal)

        store = SidewalkCertsOnHsm(self.mock_session, TEST_PRODUCT)

        self.assertEqual(store.get_certificate(
            CA_TYPE.AMZN, STAGE.PROD, CURVE.ED25519), chain_ed25519[0])
        self.assertEqual(store.get_certificate(
            CA_TYPE.SIDEWALK, STAGE.PROD, CURVE.ED25519), chain_ed25519[1])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MAN, STAGE.PROD, CURVE.ED25519), chain_ed25519[2])
        self.assertEqual(store.get_certificate(
            CA_TYPE.PROD, STAGE.PROD, CURVE.ED25519), chain_ed25519[3])
        self.assertEqual(store.get_certificate(
            CA_TYPE.DAK, STAGE.PROD, CURVE.ED25519), chain_ed25519[4])

        self.assertEqual(store.get_certificate(
            CA_TYPE.AMZN, STAGE.PROD, CURVE.P256R1), chain_p256r1[0])
        self.assertEqual(store.get_certificate(
            CA_TYPE.SIDEWALK, STAGE.PROD, CURVE.P256R1), chain_p256r1[1])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MAN, STAGE.PROD, CURVE.P256R1), chain_p256r1[2])
        self.assertEqual(store.get_certificate(
            CA_TYPE.PROD, STAGE.PROD, CURVE.P256R1), chain_p256r1[3])
        self.assertEqual(store.get_certificate(
            CA_TYPE.DAK, STAGE.PROD, CURVE.P256R1), chain_p256r1[4])

    def test_get_certificate_legacy(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains('dummy_certs_legacy.json')

        def cert_equal(cert1, cert2, msg=None):
            if (cert1.serial != cert2.serial
                or cert1.pubk != cert2.pubk
                    or cert1.signature != cert2.signature):
                raise self.failureException(msg)
        self.addTypeEqualityFunc(SidewalkCert, cert_equal)

        store = SidewalkCertsOnHsm(self.mock_session_legacy, TEST_PRODUCT_LEGACY)

        self.assertEqual(store.get_certificate(
            CA_TYPE.AMZN, STAGE.PROD, CURVE.ED25519), chain_ed25519[0])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MAN, STAGE.PROD, CURVE.ED25519), chain_ed25519[1])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MODEL, STAGE.PROD, CURVE.ED25519), chain_ed25519[2])

        self.assertEqual(store.get_certificate(
            CA_TYPE.AMZN, STAGE.PROD, CURVE.P256R1), chain_p256r1[0])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MAN, STAGE.PROD, CURVE.P256R1), chain_p256r1[1])
        self.assertEqual(store.get_certificate(
            CA_TYPE.MODEL, STAGE.PROD, CURVE.P256R1), chain_p256r1[2])

    def test_get_cert_chains(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains('dummy_certs.json')

        store = SidewalkCertsOnHsm(self.mock_session, TEST_PRODUCT)

        # JSON has DEVICE but HSM doesn't
        chain_ed25519.pop()
        chain_p256r1.pop()

        self.assertEqual(store.get_certificate_chain(
            STAGE.PROD, CURVE.ED25519).get_raw(), chain_ed25519.get_raw())
        self.assertEqual(store.get_certificate_chain(
            STAGE.PROD, CURVE.P256R1).get_raw(), chain_p256r1.get_raw())

    def test_get_cert_chains_legacy(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains('dummy_certs_legacy.json')

        store = SidewalkCertsOnHsm(self.mock_session_legacy, TEST_PRODUCT_LEGACY)

        # JSON has DEVICE but HSM doesn't
        chain_ed25519.pop()
        chain_p256r1.pop()

        self.assertEqual(store.get_certificate_chain(
            STAGE.PROD, CURVE.ED25519).get_raw(), chain_ed25519.get_raw())
        self.assertEqual(store.get_certificate_chain(
            STAGE.PROD, CURVE.P256R1).get_raw(), chain_p256r1.get_raw())

    def test_cached_hsm_content(self):
        store_cached = SidewalkCertsOnHsm(self.mock_session, TEST_PRODUCT, load_hsm_cache('hsm_content.json'))
        store = SidewalkCertsOnHsm(self.mock_session, TEST_PRODUCT)

        self.assertEqual(
            store.get_certificate_chain(STAGE.PROD, CURVE.ED25519).get_raw(),
            store_cached.get_certificate_chain(STAGE.PROD, CURVE.ED25519).get_raw())

        self.assertEqual(
            store.get_certificate_chain(STAGE.PROD, CURVE.P256R1).get_raw(),
            store_cached.get_certificate_chain(STAGE.PROD, CURVE.P256R1).get_raw())

class TestUtilities(unittest.TestCase):
    def test_smsn_generator(self):
        smsn = sidewalk_signing_tool.generate_smsn(
            STAGE.PROD, "DUMMY", "FAKE_APID", "FAKE_DSN")
        self.assertEqual(str(hexlify(smsn), 'ascii'), "1f4ee02cd76fed7f9f30b02169e582f6685970c76d33b48b7951dd5a555b7ec6")

    def test_load_private_key_from_pem(self):
        with open(os.path.join(TEST_DIR, 'test_ed25519_priv.pem'), 'rb') as f:
            priv, pubk = sidewalk_signing_tool.load_private_key_from_pem(f.read(), CURVE.ED25519)
            self.assertEqual(priv,
                             bytes.fromhex("74616516298c6edbf71be8fbcd2221a2f90d4229e67dad8639b7db2e80ff8385"))
            self.assertEqual(pubk,
                             bytes.fromhex("c8ad677893b0ea74ca44d0d5c875dbb2e61625be4d1cd36759f1e5972fd6edcb"))

        with open(os.path.join(TEST_DIR, 'test_p256r1_priv.pem'), 'rb') as f:
            priv, pubk = sidewalk_signing_tool.load_private_key_from_pem(f.read(), CURVE.P256R1)
            self.assertEqual(priv,
                             bytes.fromhex("bc25e2a273d5340f5481615c206d9b5e8aa7ab0f11de0d5810b0dfc7f7e18166"))
            self.assertEqual(pubk,
                             bytes.fromhex("3b78d18aeb65c68562345db066f9c564bf68f88fb6289e30fb738167086cae12"
                                           "1b580af96806975bd6575ee892fe514e57bdfcd07f56dc1115130a4914262d53"))

    def test_verify_with_sig_ed25519(self):
        data = b'test data'
        pubk = bytes.fromhex("c06e9dd619cb14a80f2986ac56baa5f987807993eda2541a0efc65cb452f7ec4")
        signature = bytes.fromhex("d9c9547d4aae4d283e4683a87186c5ec2b4e0bf3bcbee006487de130c28c55015b3314b858b0ec0054913935493c7052dfc30f619432eb095d42b41ea388e90b")
        sidewalk_signing_tool.verify_with_sig_ed25519(pubk, signature, data)
        with self.assertRaises(InvalidSignature):
            sidewalk_signing_tool.verify_with_sig_ed25519(pubk, signature[:-1]+b'0', data)

    def test_verify_with_sig_p256r1(self):
        data = b'test data'
        pubk = bytes.fromhex("bca86f9a0e7a443ebdc2280a304742243985a4b07bb211e98b3901004cfe46785b02d501248e8887a367892e2af2e44cf1b39417a9f1cef96807f1a2f5f91142")
        signature = bytes.fromhex("24632551df098e6100fc859cd8de73b4758dda9d7535d7360235629f3d7b474a5612a5450099a4df7d33b09288caf1e90e7c265b4e2d96f34c3a1ccd8de80e98")
        sidewalk_signing_tool.verify_with_sig_p256r1(pubk, signature, data)
        with self.assertRaises(InvalidSignature):
            sidewalk_signing_tool.verify_with_sig_p256r1(pubk, signature[:-1]+b'0', data)

    def test_decode_csr(self):
        csr_smsn = bytes.fromhex("35f59d25e512bb41c136ad759a0f92790beed1a7efbad5ace827051cea482a2a")
        csr_pubk_ed25519 = bytes.fromhex("c06e9dd619cb14a80f2986ac56baa5f987807993eda2541a0efc65cb452f7ec4")
        csr_pubk_p256r1 = bytes.fromhex("bca86f9a0e7a443ebdc2280a304742243985a4b07bb211e98b3901004cfe46785b02d501248e8887a367892e2af2e44cf1b39417a9f1cef96807f1a2f5f91142")
        csr_sig_ed25519 = bytes.fromhex("f27806eaeb34f081379e03b6ef4fdf44d935f9d6d907b9f1852defe14e15bcc9497cfa5ae7cf855b54c812bb690828a7062bedb11710d98cdf01eb610f819703")
        csr_sig_p256r1 = bytes.fromhex("4ec618fba313294ed23541658df5243f9b26193b6012114fedc1b00b2179513ead9dd8ed1c1c5c3a8d4e2f9ca74a5eb3c3ac60542db165d6a3c9cb77c45dad37")

        # CSR contains PUBK only
        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_ed25519, 0, CURVE.ED25519)
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, bytes())
        self.assertEqual(sig, bytes())

        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_p256r1, 0, CURVE.P256R1)
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, bytes())
        self.assertEqual(sig, bytes())

        # CSR contains PUBK + SN
        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_ed25519+csr_smsn, 32, CURVE.ED25519)
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, bytes())

        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_p256r1+csr_smsn, 32, CURVE.P256R1)
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, bytes())

        # CSR contains PUBK + SN + PUBK
        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_ed25519+csr_smsn+csr_sig_ed25519, 32, CURVE.ED25519)
        self.assertEqual(pubk, csr_pubk_ed25519)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, csr_sig_ed25519)

        (pubk, smsn, sig) = sidewalk_signing_tool.decode_csr(csr_pubk_p256r1+csr_smsn+csr_sig_p256r1, 32, CURVE.P256R1)
        self.assertEqual(pubk, csr_pubk_p256r1)
        self.assertEqual(smsn, csr_smsn)
        self.assertEqual(sig, csr_sig_p256r1)

        # Invalid length
        with self.assertRaises(ValueError):
            sidewalk_signing_tool.decode_csr(b'\0'*16, 0, CURVE.P256R1)

        with self.assertRaises(ValueError):
            sidewalk_signing_tool.decode_csr(b'\0'*256, 0, CURVE.P256R1)

        # Invalid signature
        with self.assertRaises(InvalidSignature):
            sidewalk_signing_tool.decode_csr(csr_pubk_ed25519+csr_smsn+b'\0'*len(csr_sig_ed25519), 32, CURVE.ED25519)

        with self.assertRaises(InvalidSignature):
            sidewalk_signing_tool.decode_csr(csr_pubk_p256r1+csr_smsn+b'\0'*len(csr_sig_p256r1), 32, CURVE.P256R1)


