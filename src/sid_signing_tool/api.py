# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import binascii
import logging

from cryptography.exceptions import InvalidSignature

from sid_signing_tool import crypto, exceptions, util
from sid_signing_tool.cert import SidewalkCert
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


def decode_csr(csr, smsn_len, curve, verify_sig=True):
    if curve == CURVE.ED25519:
        pubk_len = ED25519_PUBK_LEN
        sig_len = ED25519_SIG_LEN
    elif curve == CURVE.P256R1:
        pubk_len = P256R1_PUBK_LEN
        sig_len = P256R1_SIG_LEN

    if len(csr) == pubk_len + smsn_len:
        sig_len = 0

    if len(csr) != pubk_len + smsn_len + sig_len:
        raise exceptions.InvalidCSRLength(
            "Invalid length of CSR for curve=%r, got %d" % (curve, len(csr))
        )

    pubk = csr[0:pubk_len]
    csr = csr[pubk_len:]
    smsn = csr[:smsn_len]
    csr = csr[smsn_len:]
    sig = csr[:sig_len]

    # For on device cert gen, check if the CSRs are valid
    if verify_sig and len(sig):
        if curve == CURVE.ED25519:
            crypto.verify_with_sig_ed25519(pubk, sig, pubk + smsn)
        if curve == CURVE.P256R1:
            crypto.verify_with_sig_p256r1(pubk, sig, pubk + smsn)

    logger.info(
        "Decoding CSR for %r: pubk=%s,smsn=%s,sig=%s"
        % (
            curve,
            str(binascii.hexlify(pubk), "ascii"),
            str(binascii.hexlify(smsn), "ascii"),
            str(binascii.hexlify(sig), "ascii"),
        )
    )
    return (pubk, smsn, sig)


def sign_csr(
    ed25519_csr,
    p256r1_csr,
    cert_store,
    sn_len=SMSN_LEN,
    stage=None,
    dsn=None,
    apid=None,
    device_type_id=None,
    validate_chain=True,
):
    if not ed25519_csr or not p256r1_csr or not p256r1_csr:
        raise ValueError("Missing arguments")

    try:
        (ed25519_csr_pubk, ed25519_csr_sn, ed25519_csr_sig) = decode_csr(
            ed25519_csr, sn_len, CURVE.ED25519
        )
    except (InvalidSignature, ValueError):
        raise exceptions.InvalidEddsaCSR("Invalid eddsa_csr. Bad key or signature")

    try:
        (p256r1_csr_pubk, p256r1_csr_sn, p256r1_csr_sig) = decode_csr(
            p256r1_csr, sn_len, CURVE.P256R1
        )
    except (InvalidSignature, ValueError):
        raise exceptions.InvalidEcdsaCSR("Invalid ecdsa_csr. Bad key or signature")

    if (ed25519_csr_sig and not p256r1_csr_sig) or (p256r1_csr_sig and not ed25519_csr_sig):
        raise ValueError("Only one of CSRs has the signature")

    if sn_len == 0:
        logger.info(
            f"Generate SMSN using stage={stage!r}, device_type={device_type_id}, apn={apid}, dsn={dsn}"
        )
        smsn = util.generate_smsn(stage, device_type_id, apid, dsn)
    else:
        if ed25519_csr_sn != p256r1_csr_sn:
            raise ValueError("Serials in both CSRs do not match")
        smsn = ed25519_csr_sn

    logger.info(f"SMSN={str(binascii.hexlify(smsn))}")
    logger.info(
        f"Generate certificate chain for ed25519 with {str(binascii.hexlify(ed25519_csr_pubk), 'ascii')}..."
    )
    ed25519_chain = generate_chain(CURVE.ED25519, ed25519_csr_pubk, smsn, cert_store)

    logger.info(
        f"Generate certificate chain for p256r1 with {str(binascii.hexlify(p256r1_csr_pubk), 'ascii')}..."
    )
    p256r1_chain = generate_chain(CURVE.P256R1, p256r1_csr_pubk, smsn, cert_store)

    logger.info("Validating the result...")
    if validate_chain:
        ed25519_chain.validate()
        p256r1_chain.validate()

    result = {
        "smsn": smsn,
        "ed25519_device_pubk": ed25519_csr_pubk,
        "p256r1_device_pubk": p256r1_csr_pubk,
        "ed25519_chain": ed25519_chain.get_raw(),
        "p256r1_chain": p256r1_chain.get_raw(),
    }

    return result


def generate_chain(curve, device_pubk, smsn, cert_store):
    logger.info(f"Pulling the chain for {curve!r} from the cert store")
    chain = cert_store.get_certificate_chain(curve)

    logger.info(f"Signing the device cert for {curve!r}")
    device_cert = SidewalkCert(
        type=CATYPE.DEVICE,
        curve=curve,
        serial=smsn,
        pubk=device_pubk,
        signature=cert_store.sign(curve, device_pubk + smsn),
    )

    # Make the complete chain
    chain.append(device_cert)

    return chain
