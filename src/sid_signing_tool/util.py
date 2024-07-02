# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from cryptography.hazmat.primitives import hashes

from sid_signing_tool.types import STAGE


def generate_smsn(stage, device_type, apid, dsn):
    if stage is None or not dsn or not apid or not device_type:
        raise ValueError("Missing essential components for generating SMSN")
    hasher = hashes.Hash(hashes.SHA256())
    hasher.update((device_type + "-" + stage2str(stage) + dsn + apid).encode("ascii"))
    return hasher.finalize()


def stage2str(stage):
    str = ""
    if stage == STAGE.PROD:
        str = "PRODUCTION"
    elif stage == STAGE.TEST:
        str = "TEST"
    elif stage == STAGE.PREPROD:
        str = "PREPRODUCTION"
    return str
