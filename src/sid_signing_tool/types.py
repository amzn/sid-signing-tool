# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

SMSN_LEN = 32
ED25519_PUBK_LEN = 32
P256R1_PUBK_LEN = 64
ED25519_SIG_LEN = 64
P256R1_SIG_LEN = 64


class CURVE(object):
    """
    String values are used in implementations and must not be changed
    """

    ED25519 = "ed25519"
    P256R1 = "p256r1"


class STAGE(object):
    """
    String values are used in implementations and must not be changed
    """

    PROD = "prod"
    TEST = "test"
    PREPROD = "preprod"


class ELEMENT(object):
    """
    String values are used in implementations and must not be changed
    """

    PRIV = "private"
    PUBK = "pubkey"
    SIGNATURE = "signature"
    SERIAL = "serial"


class CATYPE(object):
    """
    String values are used in implementations and must not be changed
    """

    AMZN = "amzn"
    SIDEWALK = "sidewalk"
    MAN = "man"
    PROD = "prod"
    DAK = "dak"
    DEVICE = "device"
    MODEL = "model"
