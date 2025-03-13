# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import binascii
import logging
from typing import Optional

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


def sign_encoded_csr(
    ed25519_csr: str,
    p256r1_csr: str,
    cert_store,
    sn_len: int = SMSN_LEN,
    stage: Optional[str] = None,
    dsn: Optional[str] = None,
    apid: Optional[str] = None,
    device_type_id: Optional[str] = None,
    validate_chain: bool = True,
) -> dict:
    """Sign device Certificate Signing Request (CSR) with product Device Attestation Key (DAK) using encoded output from sid_diagnostics.

    Args:
        ed25519_csr (str): Base64 encoded certificate signing request for ED25519 key.
            Must be a valid base64 encoded string containing the CSR.
        p256r1_csr (str): Base64 encoded certificate signing request for P256R1 key.
            Must be a valid base64 encoded string containing the CSR.
        cert_store: Certificate store object for managing certificates.
        sn_len (int, optional): Length of serial number.
            Defaults to SMSN_LEN.
        stage (str, optional): Sidewalk Stage.
            Valid values are ['PREPRODUCTION', 'PRODUCTION']. Defaults to None.
        dsn (str, optional): Device Serial Number.
             Defaults to None.
        apid (str, optional): Advertised Product ID.
            Must be a valid identifier. Defaults to None.
        device_type_id (str, optional): Device type identifier.
            Defaults to None.
        validate_chain (bool, optional): Whether to validate certificate chain.
            Defaults to True

    Returns:
        dict: Processed certificate information containing:
            - smsn: Hex string encoded SMSN
            - ed25519_device_pubk: Device ED25519 public key
            - p256r1_device_pubk: Device P256R1 public key
            - ed25519_chain: Base64 encoded ED25519 certificate chain
            - p256r1_chain: Base64 encoded P256R1 certificate chain

    Raises:
        InvalidEddsaCSR: If ed25519 csr validation fails
        InvalidEcdsaCSR: If p256r1 csr validation fails
        ValueError: If base64 decoding fails

    Examples:
        >>> ed_csr = "MIIBgjCCASmgAwIBAgIJAL..."  # base64 encoded CSR
        >>> result = sign_encoded_csr(
        ...     ed25519_csr=ed_csr,
        ...     p256r1_csr=p256_csr,
        ...     cert_store=store,
        ... )
    """
    try:
        decoded_ed25519_csr = base64.standard_b64decode(ed25519_csr)
        decoded_p256r1_csr = base64.standard_b64decode(p256r1_csr)
    except binascii.Error:
        raise ValueError("Invalid base64 encoding")

    result = sign_csr(
        ed25519_csr=decoded_ed25519_csr,
        p256r1_csr=decoded_p256r1_csr,
        cert_store=cert_store,
        sn_len=sn_len,
        stage=stage,
        dsn=dsn,
        apid=apid,
        device_type_id=device_type_id,
        validate_chain=validate_chain,
    )

    encoded_result = {
        "smsn": result["smsn"].hex(),
        "ed25519_device_pubk": base64.standard_b64encode(result["ed25519_device_pubk"]).decode(
            "utf-8"
        ),
        "p256r1_device_pubk": base64.standard_b64encode(result["p256r1_device_pubk"]).decode(
            "utf-8"
        ),
        "ed25519_chain": base64.standard_b64encode(result["ed25519_chain"]).decode("utf-8"),
        "p256r1_chain": base64.standard_b64encode(result["p256r1_chain"]).decode("utf-8"),
    }
    return encoded_result


def sign_csr(
    ed25519_csr: bytes,
    p256r1_csr: bytes,
    cert_store,
    sn_len: int = SMSN_LEN,
    stage: Optional[str] = None,
    dsn: Optional[str] = None,
    apid: Optional[str] = None,
    device_type_id: Optional[str] = None,
    validate_chain: bool = True,
) -> dict:
    """Sign device Certificate Signing Request (CSR) with product Device Attestation Key (DAK).

    Args:
        ed25519_csr (bytes): Certificate signing request for Ed25519 key.
            Must be a valid decoded Sidewalk Ed25519 CSR.
        p256r1_csr (bytes): Certificate signing request for P256R1 key.
            Must be a valid decoded Sidewalk P256R1 CSR.
        cert_store: Certificate store object for managing keys.
        sn_len (int, optional): Length of serial number.
            Defaults to SMSN_LEN.
        stage (str, optional): Sidewalk Stage.
            Valid values are ['PREPRODUCTION', 'PRODUCTION']. Defaults to None.
        dsn (str, optional): Device Serial Number.
             Defaults to None.
        apid (str, optional): Advertised Product ID.
            Must be a valid identifier. Defaults to None.
        device_type_id (str, optional): Device type identifier.
            Defaults to None.
        validate_chain (bool, optional): Whether to validate certificate chain.
            Defaults to True

    Returns:
        dict: Processed certificate information containing:
            - smsn: Sidewalk Manufacturing Serial Number
            - ed25519_device_pubk: Device ED25519 public key
            - p256r1_device_pubk: Device P256R1 public key
            - ed25519_chain: ED25519 certificate chain
            - p256r1_chain: P256R1 certificate chain

    Raises:
        InvalidEddsaCSR: If ed25519 csr validation fails
        InvalidEcdsaCSR: If p256r1 csr validation fails
        ValueError: If data is missing from arguments or CSRs

    Examples:
        >>> ed_csr = base64.decode("MIIBgjCCASmgAwIBAgIJAL..."  #decoded csr
        >>> result = function_name(
        ...     ed25519_csr=ed_csr,
        ...     p256r1_csr=p256_csr,
        ...     cert_store=store,
        ... )
    """

    if not ed25519_csr or not p256r1_csr or not cert_store:
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
