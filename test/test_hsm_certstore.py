# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os
import unittest
from unittest.mock import Mock, create_autospec, patch

from helpers import get_test_data_dir, load_dummy_chains
from yubihsm import YubiHsm
from yubihsm.core import AuthSession, DeviceInfo
from yubihsm.objects import ObjectInfo

from sid_signing_tool.cert import SidewalkCert
from sid_signing_tool.certstore.hsm import HsmCertStore
from sid_signing_tool.types import CATYPE, CURVE, STAGE

TEST_PRODUCT = "RNET_DAK_DUMMY"
TEST_PRODUCT_LEGACY = "RNET_MODEL_DUMMY"
TEST_CONNECTOR = "http://localhost:12345"
TEST_PIN = "1234"
TEST_STAGE = STAGE.PROD


def load_hsm_cache(file):
    hsm_content_file = os.path.join(get_test_data_dir(), file)
    with open(hsm_content_file) as f:
        return json.loads(f.read())


class TestHsmCertStore(unittest.TestCase):
    def get_mock_yubihsm_session(self, hsm_content_file):
        hsm_content = load_hsm_cache(hsm_content_file)
        object_list = []
        for k, v in hsm_content.items():
            mock_object = Mock()
            (mock_object.id, mock_object.object_type) = (v["id"], v["type"])
            mock_object.get_info.return_value = ObjectInfo(*v["info"])
            if "content" in v:
                mock_object.get.return_value = bytes.fromhex(v["content"])
            object_list.append(mock_object)

        mock_session = create_autospec(AuthSession)
        mock_session.list_objects.return_value = object_list
        return mock_session

    def get_mock_device_info(self):
        mock_device_info = create_autospec(DeviceInfo)
        mock_device_info.serial = "1234"
        return mock_device_info

    def setUp(self):
        self.mock_session = self.get_mock_yubihsm_session("hsm_content.json")
        self.mock_session_legacy = self.get_mock_yubihsm_session("hsm_content_legacy.json")
        self.mock_device_info = self.get_mock_device_info()

    def test_init_a_hsm_store(self):
        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT,
            )
            store.open()
            store.close()

    def test_init_a_hsm_store_legacy(self):
        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session_legacy
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT_LEGACY,
            )
            store.open()
            store.close()

    def test_get_certificate(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains("dummy_certs.json")

        def cert_equal(cert1, cert2, msg=None):
            if (
                cert1.serial != cert2.serial
                or cert1.pubk != cert2.pubk
                or cert1.signature != cert2.signature
            ):
                raise self.failureException(msg)

        self.addTypeEqualityFunc(SidewalkCert, cert_equal)

        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT,
            )
            store.open()

            self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.ED25519), chain_ed25519[0])
            self.assertEqual(
                store.get_certificate(CATYPE.SIDEWALK, CURVE.ED25519), chain_ed25519[1]
            )
            self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.ED25519), chain_ed25519[2])
            self.assertEqual(store.get_certificate(CATYPE.PROD, CURVE.ED25519), chain_ed25519[3])
            self.assertEqual(store.get_certificate(CATYPE.DAK, CURVE.ED25519), chain_ed25519[4])

            self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.P256R1), chain_p256r1[0])
            self.assertEqual(store.get_certificate(CATYPE.SIDEWALK, CURVE.P256R1), chain_p256r1[1])
            self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.P256R1), chain_p256r1[2])
            self.assertEqual(store.get_certificate(CATYPE.PROD, CURVE.P256R1), chain_p256r1[3])
            self.assertEqual(store.get_certificate(CATYPE.DAK, CURVE.P256R1), chain_p256r1[4])

            store.close()

    def test_get_certificate_legacy(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains("dummy_certs_legacy.json")

        def cert_equal(cert1, cert2, msg=None):
            if (
                cert1.serial != cert2.serial
                or cert1.pubk != cert2.pubk
                or cert1.signature != cert2.signature
            ):
                raise self.failureException(msg)

        self.addTypeEqualityFunc(SidewalkCert, cert_equal)

        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session_legacy
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT_LEGACY,
            )
            store.open()

            self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.ED25519), chain_ed25519[0])
            self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.ED25519), chain_ed25519[1])
            self.assertEqual(store.get_certificate(CATYPE.MODEL, CURVE.ED25519), chain_ed25519[2])

            self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.P256R1), chain_p256r1[0])
            self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.P256R1), chain_p256r1[1])
            self.assertEqual(store.get_certificate(CATYPE.MODEL, CURVE.P256R1), chain_p256r1[2])

            store.close()

    def test_get_cert_chains(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains("dummy_certs.json")

        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT,
            )
            store.open()

            # JSON has DEVICE but HSM doesn't
            chain_ed25519.pop()
            chain_p256r1.pop()

            self.assertEqual(
                store.get_certificate_chain(CURVE.ED25519).get_raw(),
                chain_ed25519.get_raw(),
            )
            self.assertEqual(
                store.get_certificate_chain(CURVE.P256R1).get_raw(),
                chain_p256r1.get_raw(),
            )

            store.close()

    def test_get_cert_chains_legacy(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains("dummy_certs_legacy.json")

        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session_legacy
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT_LEGACY,
            )
            store.open()

            # JSON has DEVICE but HSM doesn't
            chain_ed25519.pop()
            chain_p256r1.pop()

            self.assertEqual(
                store.get_certificate_chain(CURVE.ED25519).get_raw(),
                chain_ed25519.get_raw(),
            )
            self.assertEqual(
                store.get_certificate_chain(CURVE.P256R1).get_raw(),
                chain_p256r1.get_raw(),
            )

            store.close()

    def test_cached_hsm_content(self):
        with patch.object(
            YubiHsm, "create_session_derived", return_value=self.mock_session
        ), patch.object(YubiHsm, "get_device_info", return_value=self.mock_device_info):
            store_cached = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT,
            )
            store = HsmCertStore(
                connector=TEST_CONNECTOR,
                pin=TEST_PIN,
                stage=TEST_STAGE,
                signer_tag=TEST_PRODUCT,
            )
            store_cached.open()
            store.open()

            self.assertEqual(
                store.get_certificate_chain(CURVE.ED25519).get_raw(),
                store_cached.get_certificate_chain(CURVE.ED25519).get_raw(),
            )

            self.assertEqual(
                store.get_certificate_chain(CURVE.P256R1).get_raw(),
                store_cached.get_certificate_chain(CURVE.P256R1).get_raw(),
            )

            store_cached.close()
            store.close()
