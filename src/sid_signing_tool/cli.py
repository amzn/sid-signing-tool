# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import base64
import binascii
import json
import logging
import sys
import time
from collections import defaultdict
from enum import IntEnum, auto
from os import path

from cryptography.exceptions import InvalidSignature
from packaging import version
from yubihsm.exceptions import (
    YubiHsmAuthenticationError,
    YubiHsmConnectionError,
    YubiHsmDeviceError,
)

from sid_signing_tool import api, crypto, exceptions, util
from sid_signing_tool.certstore.hsm import HsmCertStore
from sid_signing_tool.types import CURVE, SMSN_LEN, STAGE

logger = logging.getLogger(__name__)

__version__ = "1.2.0"


class HSM_VERSION(IntEnum):
    LEGACY = 0
    LONG_CHAIN = 1
    PREPROD = 2


def arg_parser_builder():
    def base64str(val):
        try:
            return base64.standard_b64decode(val)
        except binascii.Error:
            raise argparse.ArgumentTypeError("unable to decode")

    def hexstr(val):
        try:
            return bytes.fromhex(val)
        except binascii.Error:
            raise argparse.ArgumentTypeError("unable to decode")

    def filepath(val):
        try:
            with open(val) as tempfile:
                return val
        except:
            raise argparse.ArgumentTypeError("unable to open file")

    def lenth_of_data(val):
        length = int(val)
        if length <= 0:
            raise argparse.ArgumentTypeError("must be greater than 0")
        return length

    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument(
        "-V", "--version", action="version", version=__version__, help="Print version and exit"
    )

    parser.add_argument(
        "-p", "--product", required=True, help="Label of the product defined in the HSM"
    )

    parser.add_argument("--pin", required=True, help="Pin for the HSM signing domain")

    parser.add_argument("--pin_slot", type=int, help="Key slot that PIN will be authenticated with")

    parser.add_argument("--eddsa_csr", type=base64str, help="Ed25519 Certificate Signing Request")

    parser.add_argument("--ecdsa_csr", type=base64str, help="P256R1 Certifiate Signing Request")

    parser.add_argument("-c", "--connector", required=True, help="URL of the yubihsm-connector")

    parser.add_argument("--ca_cert", type=filepath, help="CA of the yubihsm-connector for HTTPS")

    parser.add_argument(
        "--client_cert",
        type=filepath,
        help="Certificate the client presents for authentication for HTTPS",
    )

    parser.add_argument(
        "--client_key",
        type=filepath,
        help="Key the client presents for authentication for HTTPS",
    )

    parser.add_argument(
        "-s",
        "--smsn_len",
        type=lenth_of_data,
        default=SMSN_LEN,
        help="Length of the Sidewalk Manufacturing Serial Number \
                              or device certificate subject",
    )

    parser.add_argument(
        "-g",
        "--generate_smsn",
        action="store_true",
        help="Generate a Sidewalk Manufacturing Serial Number",
    )

    parser.add_argument("-d", "--device_type", help="Device Type of the product")

    parser.add_argument("-D", "--dsn", help="Unique serial number for the device")

    parser.add_argument("-a", "--apid", help="The Advertised Product ID")

    parser.add_argument(
        "--outform",
        choices=["json", "flat"],
        default="json",
        help="The output format of the data",
    )

    parser.add_argument(
        "--control_log_dir",
        type=str,
        help="The path to save auto-generated control log",
    )

    parser.add_argument(
        "--control_log_ver",
        type=str,
        default="4-0-1",
        help="The version in which the control log to be generated",
    )

    parser.add_argument(
        "-o",
        type=argparse.FileType("w"),
        default="-",
        help="Output the signing data to a file",
    )

    parser.add_argument("--ed25519_private_key", type=hexstr, help="The ED25519 private key")

    parser.add_argument("--p256r1_private_key", type=hexstr, help="The P256R1 private key")

    parser.add_argument(
        "--ed25519_private_key_file",
        type=argparse.FileType("rb"),
        help="The ED25519 private key",
    )

    parser.add_argument(
        "--p256r1_private_key_file",
        type=argparse.FileType("rb"),
        help="The P256R1 private key",
    )

    parser.add_argument(
        "--device_profile_json",
        type=argparse.FileType("r"),
        help="Json response of 'aws iotwireless get-device-profile ...' ",
    )

    parser.add_argument(
        "--cache_cert",
        action="store_true",
        help="Cache the certificates to reduce access to HSM",
    )

    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose mode")

    parser.add_argument(
        "--verify_cert",
        type=int,
        choices=[0, 1],
        default=1,
        help="Verify generated certificate with loaded certificate chain",
    )

    parser.add_argument("--test_cert", action="store_true", help="Use test certificates in HSM")

    return parser


def generate_cl_filename():
    return "C_CONTROL_LOG_" + time.strftime("%Y%m%d%H%M%S", time.localtime()) + ".txt"


def bin2hexstr(binary):
    return str(binascii.hexlify(binary), "ascii")


def bin2base64(binary):
    return str(base64.b64encode(binary), "ascii")


def output_formatter_json(output):
    d = defaultdict(dict)
    d["eD25519"] = bin2base64(output["ed25519_chain"])
    d["p256R1"] = bin2base64(output["p256r1_chain"])
    d["label"] = util.stage2str(output["stage"]).lower()
    if output["smsn"]:
        d["metadata"]["smsn"] = bin2hexstr(output["smsn"])
    if output["apid"]:
        d["metadata"]["apid"] = output["apid"]
    if output["ed25519_priv"]:
        d["metadata"]["devicePrivKeyEd25519"] = bin2hexstr(output["ed25519_priv"])
    if output["p256r1_priv"]:
        d["metadata"]["devicePrivKeyP256R1"] = bin2hexstr(output["p256r1_priv"])
    if output["application_server_public_key"]:
        d["applicationServerPublicKey"] = bin2hexstr(output["application_server_public_key"])
    return json.dumps(d, indent=4) + "\n"


def output_formatter_flat(output):
    str = ""
    if output["smsn"]:
        str += "smsn: " + bin2hexstr(output["smsn"]) + "\n"
    if output["ed25519_priv"]:
        str += "devicePrivKeyEd25519: " + bin2hexstr(output["ed25519_priv"]) + "\n"
    if output["p256r1_priv"]:
        str += "devicePrivKeyP256R1: " + bin2hexstr(output["p256r1_priv"]) + "\n"
    str += "ED25519 Sidewalk Certificate Chain: " + bin2base64(output["ed25519_chain"]) + "\n"
    str += "P256R1 Sidewalk Certificate Chain: " + bin2base64(output["p256r1_chain"]) + "\n"
    str += "Label: " + util.stage2str(output["stage"]).lower() + "\n"
    if output["application_server_public_key"]:
        str += (
            "Application Server Public Key:"
            + bin2hexstr(output["application_server_public_key"])
            + "\n"
        )

    return str


def output_formatter_cl_4_0_1(output):
    j = {
        "controlLogs": [
            {
                "version": "4-0-1",
                "device": {
                    "serialNumber": bin2hexstr(output["smsn"]),
                    "productIdentifier": {"advertisedProductId": output["apid"]},
                    "sidewalkData": {
                        "sidewalkED25519CertificateChain": bin2base64(output["ed25519_chain"]),
                        "sidewalkP256R1CertificateChain": bin2base64(output["p256r1_chain"]),
                        "label": util.stage2str(output["stage"]).lower(),
                    },
                },
            }
        ]
    }
    return json.dumps(j, indent=2) + "\n"


def main():
    cl_output_formatters = {"4-0-1": output_formatter_cl_4_0_1}

    args = arg_parser_builder().parse_args()

    if args.verbose > 0:
        logging.basicConfig(level="DEBUG" if args.verbose >= 2 else "INFO")

    # Tests on the arguments
    if args.generate_smsn:
        if args.smsn_len != SMSN_LEN:
            sys.exit("smsn_len not valid when generating smsn")
        if args.device_type is None or args.dsn is None or args.apid is None:
            sys.exit("needs device_type, dsn, and apid when generating smsn")

    if args.control_log_dir:
        if not path.isdir(args.control_log_dir):
            sys.exit("%s doesn't exist" % args.control_log_dir)
        if args.control_log_ver not in cl_output_formatters:
            sys.exit("Unsupported control log version %s" % args.control_log_ver)
        if args.apid is None:
            sys.exit("APID need to be availabe to generate control logs")

    if (args.client_cert is None) != (args.client_key is None):
        sys.exit("Both of clent cert and key should be provided")

    if args.ed25519_private_key is not None and args.ed25519_private_key_file is not None:
        sys.exit("Both ed25519_private_key_file and ed25519_private_key provided")

    if args.p256r1_private_key is not None and args.p256r1_private_key_file is not None:
        sys.exit("Both p256r1_private_key_file and p256r1_private_key provided")

    if args.eddsa_csr is None and args.ed25519_private_key_file is None:
        sys.exit(
            "Public key for eddsa should be provided --eddsa_csr or --ed25519_private_key_file"
        )

    if args.ecdsa_csr is None and args.p256r1_private_key_file is None:
        sys.exit("Public key for ecdsa should be provided --ecdsa_csr or --p256r1_private_key_file")

    if (args.ecdsa_csr and not args.eddsa_csr) or (args.eddsa_csr and not args.ecdsa_csr):
        sys.exit("Both of CSRs should be provided")

    if args.eddsa_csr is None and not args.generate_smsn:
        sys.exit("Need --generate_smsn as no CSR is provided")

    # Prepare keys
    # Public key: from CSR or PEM (with -g, the user can just provide no CSR)
    # Private key: from argument or PEM

    ed25519_priv = None
    p256r1_priv = None
    application_server_public_key = None

    if args.device_profile_json is not None:
        device_profile = json.loads(args.device_profile_json.read())
        application_server_public_key = binascii.unhexlify(
            device_profile["Sidewalk"]["ApplicationServerPublicKey"]
        )

    if args.ed25519_private_key_file is not None:
        (ed25519_priv, ed25519_pubk) = crypto.load_private_key_from_pem(
            args.ed25519_private_key_file.read(), CURVE.ED25519
        )
        logger.debug(
            "Loaded ed25519 priv: " + str(base64.standard_b64encode(ed25519_priv), "ascii")
        )
        logger.debug(
            "Loaded ed25519 pubk: " + str(base64.standard_b64encode(ed25519_pubk), "ascii")
        )
        ed25519_csr = ed25519_pubk
    elif args.ed25519_private_key is not None:
        ed25519_priv = args.ed25519_private_key

    if args.p256r1_private_key_file is not None:
        (p256r1_priv, p256r1_pubk) = crypto.load_private_key_from_pem(
            args.p256r1_private_key_file.read(), CURVE.P256R1
        )
        logger.debug("Loaded p256r1 priv: " + str(base64.standard_b64encode(p256r1_priv), "ascii"))
        logger.debug("Loaded p256r1 pubk: " + str(base64.standard_b64encode(p256r1_pubk), "ascii"))
        p256r1_csr = p256r1_pubk
    elif args.p256r1_private_key is not None:
        p256r1_priv = args.p256r1_private_key

    if args.product.startswith("RNET_"):
        stage = STAGE.PROD
    elif args.product.startswith("PREPROD_"):
        stage = STAGE.PREPROD
    elif args.product.startswith("TEST_") or args.test_cert:
        stage = STAGE.TEST
    else:
        sys.exit("Unable to determine the stage from the product tag %s." % args.product)

    # Signing and pull out the chain
    cert_store = HsmCertStore(
        args.connector,
        args.pin,
        stage,
        signer_tag=args.product,
        pin_slot=args.pin_slot,
        ca_cert=args.ca_cert,
        client_cert=args.client_cert,
        client_key=args.client_key,
    )

    try:
        cert_store.open()
    except YubiHsmConnectionError as e:
        sys.exit("HSM connector error: %s" % e)
    except YubiHsmAuthenticationError as e:
        sys.exit("PIN of the HSM may be wrong")

    if isinstance(cert_store, HsmCertStore) and version.parse(__version__) < version.parse(
        cert_store._toolreq
    ):
        sys.exit("The HSM needs signing tools newer than %s to work" % cert_store._toolreq)

    signing_result = api.sign_csr(
        ed25519_csr=args.eddsa_csr or ed25519_csr,
        p256r1_csr=args.ecdsa_csr or p256r1_csr,
        cert_store=cert_store,
        sn_len=(0 if args.generate_smsn else args.smsn_len),
        stage=stage,
        device_type_id=args.device_type,
        apid=args.apid,
        dsn=args.dsn,
        validate_chain=args.verify_cert > 0,
    )

    logger.info("Generated/Grabbed SMSN=" + str(binascii.hexlify(signing_result["smsn"]), "ascii"))

    # Check the public key and the private key, if provided
    if args.verify_cert:
        test_data = b"test data"
        if ed25519_priv is not None:
            signature = crypto.sign_ed25519(ed25519_priv, test_data)
            try:
                crypto.verify_with_sig_ed25519(
                    signing_result["ed25519_device_pubk"], signature, test_data
                )
            except InvalidSignature:
                sys.exit("The private key of eddsa provided doesn't match the public key in CSR")

        if p256r1_priv is not None:
            signature = crypto.sign_p256r1(p256r1_priv, test_data)
            try:
                crypto.verify_with_sig_p256r1(
                    signing_result["p256r1_device_pubk"], signature, test_data
                )
            except InvalidSignature:
                sys.exit("The private key of ecdsa provided doesn't match the public key in CSR")

    # Collect what we have and generate the output
    output = {
        "ed25519_chain": signing_result["ed25519_chain"],
        "p256r1_chain": signing_result["p256r1_chain"],
        "smsn": signing_result["smsn"],
        "stage": stage,
        "apid": args.apid,
        "ed25519_priv": ed25519_priv,
        "p256r1_priv": p256r1_priv,
        "application_server_public_key": application_server_public_key,
    }

    if args.outform == "json":
        args.o.write(output_formatter_json(output))
    else:
        args.o.write(output_formatter_flat(output))

    if args.control_log_dir:
        while True:
            # Never overwrite an existing control log file
            cl_path = path.join(args.control_log_dir, generate_cl_filename())
            if not path.isfile(cl_path):
                break
            # Wait for a while so that the filename will change
            time.sleep(1)
        with open(cl_path, "w") as f:
            f.write(cl_output_formatters[args.control_log_ver](output))
            print("CONTROL_LOG: " + cl_path)

    cert_store.close()


if __name__ == "__main__":
    main()
