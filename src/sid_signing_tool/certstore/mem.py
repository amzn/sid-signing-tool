# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

import sid_signing_tool.crypto as crypto
from sid_signing_tool import exceptions
from sid_signing_tool.cert import SidewalkCert, SidewalkCertChain
from sid_signing_tool.types import CATYPE, CURVE, ELEMENT

logger = logging.getLogger(__name__)


class MemCertStore:
    def __init__(self, cert_data):
        self._cert_data = cert_data

    def open(self):
        pass

    def close(self):
        pass

    def sign(self, curve, data):
        priv = self._cert_data[curve][CATYPE.DAK][ELEMENT.PRIV]
        if curve == CURVE.ED25519:
            logger.debug("Signing eddsa with DAK IN RAM")
            return crypto.sign_ed25519(ed25519_priv=priv, data=data)
        elif curve == CURVE.P256R1:
            logger.debug("Signing ecdsa with DAK in RAM")
            return crypto.sign_p256r1(p256r1_priv=priv, data=data)

    def get_certificate(self, type, curve):
        try:
            cert_data = self._cert_data[curve][type]
            cert = SidewalkCert(
                type=type,
                curve=curve,
                serial=cert_data[ELEMENT.SERIAL],
                signature=cert_data[ELEMENT.SIGNATURE],
                pubk=cert_data[ELEMENT.PUBK],
            )
        except KeyError as e:
            raise exceptions.MissingCertificateObject(
                f"missing certificate object for {curve!r} {type!r}: {e}"
            )

        return cert

    def get_certificate_chain(self, curve):
        chain = SidewalkCertChain()
        for cert_type in [
            CATYPE.AMZN,
            CATYPE.SIDEWALK,
            CATYPE.MAN,
            CATYPE.PROD,
            CATYPE.DAK,
        ]:
            logger.debug(f"Getting cert for {cert_type!r}, {curve!r}")
            chain.append(self.get_certificate(cert_type, curve))
        return chain
