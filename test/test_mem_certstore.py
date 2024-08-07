# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest

from helpers import get_cert_data, load_dummy_chains

from sid_signing_tool.cert import SidewalkCert
from sid_signing_tool.certstore.mem import MemCertStore
from sid_signing_tool.types import CATYPE, CURVE


class TestMemCertStore(unittest.TestCase):
    def test_init_a_mem_cert_store(self):
        cert_store = MemCertStore(get_cert_data())
        cert_store.open()
        cert_store.close()

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

        store = MemCertStore(get_cert_data())
        store.open()

        self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.ED25519), chain_ed25519[0])
        self.assertEqual(store.get_certificate(CATYPE.SIDEWALK, CURVE.ED25519), chain_ed25519[1])
        self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.ED25519), chain_ed25519[2])
        self.assertEqual(store.get_certificate(CATYPE.PROD, CURVE.ED25519), chain_ed25519[3])
        self.assertEqual(store.get_certificate(CATYPE.DAK, CURVE.ED25519), chain_ed25519[4])

        self.assertEqual(store.get_certificate(CATYPE.AMZN, CURVE.P256R1), chain_p256r1[0])
        self.assertEqual(store.get_certificate(CATYPE.SIDEWALK, CURVE.P256R1), chain_p256r1[1])
        self.assertEqual(store.get_certificate(CATYPE.MAN, CURVE.P256R1), chain_p256r1[2])
        self.assertEqual(store.get_certificate(CATYPE.PROD, CURVE.P256R1), chain_p256r1[3])
        self.assertEqual(store.get_certificate(CATYPE.DAK, CURVE.P256R1), chain_p256r1[4])

        store.close()

    def test_get_cert_chains(self):
        (chain_ed25519, chain_p256r1) = load_dummy_chains("dummy_certs.json")

        store = MemCertStore(get_cert_data())
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
