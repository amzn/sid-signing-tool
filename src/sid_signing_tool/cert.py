# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import logging

from cryptography.exceptions import InvalidSignature

from sid_signing_tool import crypto
from sid_signing_tool.types import (
    CATYPE,
    CURVE,
    ED25519_PUBK_LEN,
    ED25519_SIG_LEN,
    P256R1_PUBK_LEN,
    P256R1_SIG_LEN,
    SMSN_LEN,
)

logger = logging.getLogger(__name__)


class SidewalkCert:
    def __init__(self, type, curve, serial, pubk, signature):
        if curve == CURVE.ED25519:
            if len(pubk) != ED25519_PUBK_LEN or len(signature) != ED25519_SIG_LEN:
                raise ValueError(
                    "Invalid length of public key(%d) or signature(%d) of ed25519"
                    % (len(pubk), len(signature))
                )
        if curve == CURVE.P256R1:
            if len(pubk) != P256R1_PUBK_LEN or len(signature) != P256R1_SIG_LEN:
                raise ValueError(
                    "Invalid length of public key(%d) or signature(%d) of p256r1"
                    % (len(pubk), len(signature))
                )
        if type != CATYPE.DEVICE and SidewalkCert.get_serial_length(serial) != len(serial):
            parsed_len = SidewalkCert.get_serial_length(serial)
            raise ValueError("Invalid lengh of serial: %d %d" % (len(serial), parsed_len))

        self.type = type
        self.curve = curve
        self.serial = serial
        self.signature = signature
        self.pubk = pubk

    def verify(self, cert_to_verify):
        if self.curve != cert_to_verify.curve:
            raise ValueError("Curve mismatched")

        if self.curve == CURVE.ED25519:
            crypto.verify_with_sig_ed25519(
                self.pubk,
                cert_to_verify.signature,
                cert_to_verify.pubk + cert_to_verify.serial,
            )

        elif self.curve == CURVE.P256R1:
            crypto.verify_with_sig_p256r1(
                self.pubk,
                cert_to_verify.signature,
                cert_to_verify.pubk + cert_to_verify.serial,
            )

    @staticmethod
    def get_serial_length(serial):
        serial_len_without_expansion = 4
        sn = int.from_bytes(serial[0:serial_len_without_expansion], "little")
        if sn & 0xF0000000 == 0xB0000000:
            # Serial expansion is enabled
            return ((sn >> 16) & 0x7F) + 2
        return serial_len_without_expansion


class SidewalkCertChain(list):
    def validate(self):
        for i in range(len(self)):
            issuer = self[0] if i == 0 else self[i - 1]
            cert = self[i]
            logger.info(f"{issuer.type!r} is going to verify {cert.type!r}")
            try:
                issuer.verify(cert)
            except InvalidSignature:
                logger.error(
                    f"{issuer.type!r} cannot verify {cert.type} in the chain of {cert.curve}"
                )
                raise
        logger.info("The certificate chain is good")

    def get_raw(self):
        raw_chain = bytes()
        for cert in reversed(self):
            raw_chain += cert.serial
            raw_chain += cert.pubk
            raw_chain += cert.signature
        return raw_chain

    @classmethod
    def from_raw(cls, data, curve):
        def split_bytes(data, len):
            return (data[:len], data[len:])

        obj = cls()
        for ca in reversed([ca for ca in CATYPE if ca >= CATYPE.AMZN and ca <= CATYPE.DEVICE]):
            serial_len = SMSN_LEN if ca == CATYPE.DEVICE else SidewalkCert.get_serial_length(data)
            (serial, data) = split_bytes(data, serial_len)
            pubk_len = ED25519_PUBK_LEN if curve == CURVE.ED25519 else P256R1_PUBK_LEN
            (pubk, data) = split_bytes(data, pubk_len)
            sig_len = ED25519_SIG_LEN if curve == CURVE.ED25519 else P256R1_SIG_LEN
            (sig, data) = split_bytes(data, sig_len)
            obj.append(SidewalkCert(ca, curve, serial, pubk, sig))
        if len(data):
            raise ValueError("Chain is longer then expected")
        obj.reverse()
        return obj
