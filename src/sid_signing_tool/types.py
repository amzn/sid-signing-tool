# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from enum import IntEnum, auto

SMSN_LEN = 32
ED25519_PUBK_LEN = 32
P256R1_PUBK_LEN = 64
ED25519_SIG_LEN = 64
P256R1_SIG_LEN = 64


class NAMESPACE(IntEnum):
    """Each namespace can store 16 objects
    Namespace Control has auth keys and flags
    Namespace for cert has 4 certificates for EDDSA, EDDSA-test, ECDSA, ECDSA-test,
    4 objects in each
    """

    CONTROL = 0x0
    CERT_START = 0x10
    AMAZON = 0x10
    SIDEWALK = 0x20
    MAN = 0x30
    MAN_LEGACY = 0x20
    CERT_END = 0xF0


class CURVE(IntEnum):
    ED25519 = 0x0
    P256R1 = 0x1


class STAGE(IntEnum):
    PROD = 0x0
    TEST = 0x1
    PREPROD = 0x02


class ELEMENT(IntEnum):
    PRIV = 0x0
    PUBK = 0x1
    SIGNATURE = 0x2
    SERIAL = 0x3


class CATYPE(IntEnum):
    AMZN = auto()
    SIDEWALK = auto()
    MAN = auto()
    PROD = auto()
    DAK = auto()
    DEVICE = auto()
    MODEL = auto()
