# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import argparse
import json
import logging
import sys
import time

from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from yubihsm import YubiHsm
from yubihsm.defs import ALGORITHM, CAPABILITY, OBJECT
from yubihsm.exceptions import YubiHsmConnectionError, YubiHsmDeviceError
from yubihsm.objects import AsymmetricKey, AuthenticationKey, ObjectInfo, Opaque, YhsmObject

__version__ = "0.0.2"


def arg_parser_builder():
    parser = argparse.ArgumentParser(add_help=True)

    parser.add_argument("-V", "--version", action="store_true", help="Print version and exit")

    parser.add_argument(
        "-p", "--product", default="DUMMY", help="Label of the product defined in the HSM"
    )

    parser.add_argument("--pin", default="1234", help="Pin for the HSM signing domain")

    parser.add_argument(
        "-c", "--connector", default="http://localhost:12345", help="URL of the yubihsm-connector"
    )

    parser.add_argument("-v", "--verbose", action="count", default=0, help="Verbose mode")

    parser.add_argument(
        "-f",
        "--cert_json_file",
        type=argparse.FileType("r"),
        default="dummy_certs_4bsn.json",
        help="The json defines certificate chain",
    )

    parser.add_argument("--toolreq", default="1.1", help="The json defines certificate chain")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("--test_cert", action="store_true", help="Program test certificates to HSM")
    group.add_argument(
        "--preprod_cert", action="store_true", help="Program preproduction certificates to HSM"
    )

    return parser


def main():
    parser = arg_parser_builder()
    args = parser.parse_args()

    if args.version:
        sys.exit("version: " + __version__)

    if args.verbose > 0:
        logging.basicConfig(level="DEBUG" if args.verbose >= 2 else "INFO")

    certs = json.loads(args.cert_json_file.read())
    prefix = "RNET"
    if args.test_cert:
        prefix = "TEST"
    if args.preprod_cert:
        prefix = "PREPROD"

    with YubiHsm.connect(args.connector) as hsm, hsm.create_session_derived(
        1, "password"
    ) as session:

        auth_key = session.get_object(5, OBJECT.AUTHENTICATION_KEY)

        try:
            auth_key.get_info()
        except YubiHsmDeviceError:
            AuthenticationKey.put_derived(
                session,
                5,
                "SIDEWALK",
                5,
                CAPABILITY.GET_OPAQUE + CAPABILITY.SIGN_ECDSA + CAPABILITY.SIGN_EDDSA,
                CAPABILITY.NONE,
                args.pin,
            )
            hsmInfo = {
                "ver": 3,
                "toolreq": args.toolreq,
                "rel": int(time.time()),
                "longchain": True,
            }
            hsmInfoData = json.dumps(hsmInfo, separators=(",", ":")).encode("ascii")
            Opaque.put(
                session, 0x0E, "HSM_INFO", 5, CAPABILITY.NONE, ALGORITHM.OPAQUE_DATA, hsmInfoData
            )

            Opaque.put(
                session,
                0x0F,
                "SW_CTL_CHAIN_DEPTH",
                5,
                CAPABILITY.NONE,
                ALGORITHM.OPAQUE_DATA,
                b"\x05",
            )

        base = 0x10
        for ca in ["AMZN", "SIDEWALK", "MAN", "PROD", "DAK"]:
            index = base
            if args.test_cert or args.preprod_cert:
                index += 4
            for curve in ["ED25", "P256R1"]:
                for element in ["priv", "pub", "signature", "serial"]:
                    label = "%s_%s%s_%s.%s" % (
                        prefix,
                        ca,
                        "_" + args.product if ca in ["PROD", "DAK"] else "",
                        curve,
                        element,
                    )
                    data = bytes.fromhex(certs[curve][ca][element])
                    if element == "priv":
                        if ca.startswith("DAK"):
                            if curve == "ED25":
                                private_key = ed25519.Ed25519PrivateKey.from_private_bytes(data)
                            else:
                                private_key = ec.derive_private_key(
                                    int.from_bytes(data, "big"), ec.SECP256R1()
                                )

                            AsymmetricKey.put(
                                session,
                                index,
                                label,
                                5,
                                CAPABILITY.SIGN_EDDSA + CAPABILITY.SIGN_ECDSA,
                                private_key,
                            )
                    else:
                        Opaque.put(
                            session, index, label, 5, CAPABILITY.NONE, ALGORITHM.OPAQUE_DATA, data
                        )
                    index += 1
                index += 0x4
            base += 0x10

        print(
            "Completed the programming of dummy keys for %s_DAK_%s with PIN=%s"
            % (prefix, args.product, args.pin)
        )


if __name__ == "__main__":
    main()
