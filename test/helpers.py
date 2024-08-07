# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import json
import os

from sid_signing_tool.cert import SidewalkCert, SidewalkCertChain
from sid_signing_tool.types import CATYPE, CURVE, ELEMENT


def get_test_data_dir():
    return os.path.dirname(__file__)


def get_cert_data():
    certs = {
        CURVE.ED25519: {
            CATYPE.AMZN: {
                ELEMENT.PUBK: bytes.fromhex(
                    "b0de4f31e0076f3dab125c1da48092c127480203c703a7da8c1016147ca32c07"
                ),
                ELEMENT.SERIAL: bytes.fromhex("f1d803b9cd"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "243c0419db200bda917c46c5e02eeb57025463ad7f7b1ea51c6fc24940ebafde7310efcf65f6c54398a17361f2519778b69aaac27cff34c8d06098c36f16e10c"
                ),
            },
            CATYPE.SIDEWALK: {
                ELEMENT.PUBK: bytes.fromhex(
                    "8f2fd5368dba85553a1e6b219f20b2c6dd5b0cdd9403c70b616fb484c41dbcc6"
                ),
                ELEMENT.SERIAL: bytes.fromhex("3c344c41"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "9a1ac99ae4ef17b38eba599d9102a39155991e740ff0e0170c882655953a17013fc882b49e86ea711340adb32391a595ac65723f29cc084eb826c41f3d0d7f0e"
                ),
            },
            CATYPE.MAN: {
                ELEMENT.PUBK: bytes.fromhex(
                    "a684c7a3f9bff46820a7b6adbdd841ebee6ce385f5e893846b0d9565cde5d56d"
                ),
                ELEMENT.SERIAL: bytes.fromhex("7bd5d47e"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "b98aab2e6429b7671dd64d35267e39e6181cc6ec83db03edfeacdde69de48fb601946878bfef898f844782ff3b90d9a901a7d0d65cb2ef73f9e04861a0760f0e"
                ),
            },
            CATYPE.PROD: {
                ELEMENT.PUBK: bytes.fromhex(
                    "9650b5107f94d3364296e6f18ffd9df47fd5823bf29a211f51e26fe174904438"
                ),
                ELEMENT.SERIAL: bytes.fromhex("cea685b7612e76"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "8f608e3277b113ffed249b51e9d6d9079cfde60c4ea2fe5731e6ad5aa5dbd2f3d6b9e4878b1a417fb003be3bf8fa1db8895c5d50c77f4240acf3cdd01547c00b"
                ),
            },
            CATYPE.DAK: {
                ELEMENT.PRIV: bytes.fromhex(
                    "2d7cdb87749e045cfbf943af700330fc278b3cffed92a663f687df7bc098b29a"
                ),
                ELEMENT.PUBK: bytes.fromhex(
                    "ffb8a755034d80040b24ec544051dc14461ef5427fae63929807bdb6de40e814"
                ),
                ELEMENT.SERIAL: bytes.fromhex("e47c83b107"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "dbe1e087a4737c263fb6846ef86bf20f1a83f016441c981e1a8c5d81819fa05f060fdc437860bd0a9f367d3374bb2326286ca01b74c256984f8851d84d393b05"
                ),
            },
        },
        CURVE.P256R1: {
            CATYPE.AMZN: {
                ELEMENT.PUBK: bytes.fromhex(
                    "4f92832e83d69f4071287445b4972f01a6b22f75573b91455edc8039d1fe67bc8c7fa0915c97665a74f9c6c0a822864a9d234c6d0c81ae2e2816fa2dff391717"
                ),
                ELEMENT.SERIAL: bytes.fromhex("39f3c366"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "971673cea9f793626133dce89872f62ad2a20a6c2836a27358a636364b965c6b0f7fba369b6061ded2dd197e89d784a6015f749db2c2d3ca11fd40ff6e4ea02a"
                ),
            },
            CATYPE.SIDEWALK: {
                ELEMENT.PUBK: bytes.fromhex(
                    "824ac120307f32411e42e53c6131784b6c23236aceefa7c1ad03d8681f9e1914f7cbca9002395946c552b3e4e74c6116cb855cf93e836018cddd258ed768d9f0"
                ),
                ELEMENT.SERIAL: bytes.fromhex("b60504b00683"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "5653996ff5c829c9d2ee24283d3334f043ca3e19a1a0c7f7cfc1d348b65dcfa192aaf6790dcc3e9c59bdf47d140dadb8f080def70529346b714e015958d5b983"
                ),
            },
            CATYPE.MAN: {
                ELEMENT.PUBK: bytes.fromhex(
                    "a29f72ca3d2eb155c1ae200f819035791184533def297fddf441570350a5ba6c1ee2c4ce33bdadc0b537da0606c89adda5b99709380c6316485908d5be137880"
                ),
                ELEMENT.SERIAL: bytes.fromhex("4a146c70"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "dd79f47f0eb4a7dc0461cac24175ac3ef21bb5dfbeafc100558594cd9ece7749a03d380dc96a6eae043eeea586e6f290687d93bdd992ca714df951be89ee42cd"
                ),
            },
            CATYPE.PROD: {
                ELEMENT.PUBK: bytes.fromhex(
                    "361f5f69f4f130cbc23550692feb0e9ee5c0c1624aa6ca776ffb3defe8d644ba5bf75e538b1372edd942ea51e5bb672573ef75478f173ec36203f9c118f98b51"
                ),
                ELEMENT.SERIAL: bytes.fromhex("733785baf8130c"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "35e9ef93651161083fc03665e1253e75f5783bdab7d35fdf0846cf5fa54a052362a3720b1a7c2123b5a6624d10a8b5abf8895d02aaf1b1c1bbc91defbe7fa67b"
                ),
            },
            CATYPE.DAK: {
                ELEMENT.PRIV: bytes.fromhex(
                    "649ecd717a49c13db2b13a755fd20fcf09e1d9e6201f5ba84c61ab5e427a21fa"
                ),
                ELEMENT.PUBK: bytes.fromhex(
                    "7eaaf801c657eee7f29a0da87e6967f5ba0cbca3295ab145f7e030050caf842178852492b2f532475648a827538fc44c75656efeb8776744db4a81961e153b9e"
                ),
                ELEMENT.SERIAL: bytes.fromhex("6f0785bb8712b8"),
                ELEMENT.SIGNATURE: bytes.fromhex(
                    "9f4150231f2f163c72c7858d93b1e44885e2934fd9314a78fbf461f8ba15b57c6d54ada6044b4673a4481a9336e868f0178de8964704cefc9c7fcda46afdc816"
                ),
            },
        },
    }
    return certs


def load_dummy_chains(file):
    dummy_cert_file = os.path.join(get_test_data_dir(), file)
    with open(dummy_cert_file, "r") as f:
        certs = json.loads(f.read())
        chains = {"ED25": SidewalkCertChain(), "P256R1": SidewalkCertChain()}
        type_mapping = {
            "AMZN": CATYPE.AMZN,
            "SIDEWALK": CATYPE.SIDEWALK,
            "MAN": CATYPE.MAN,
            "PROD": CATYPE.PROD,
            "MODEL": CATYPE.MODEL,
            "DAK": CATYPE.DAK,
            "DEVICE": CATYPE.DEVICE,
        }

        ca_list = ["AMZN", "SIDEWALK", "MAN", "PROD", "MODEL", "DAK", "DEVICE"]

        for curve, chain in certs.items():
            for ca_str in ca_list:
                if ca_str not in chain:
                    continue
                elements = chain[ca_str]
                chains[curve].append(
                    SidewalkCert(
                        type=type_mapping[ca_str],
                        curve=CURVE.ED25519 if curve == "ED25" else CURVE.P256R1,
                        serial=bytes.fromhex(elements["serial"]),
                        pubk=bytes.fromhex(elements["pub"]),
                        signature=bytes.fromhex(elements["signature"]),
                    )
                )

        return (chains["ED25"], chains["P256R1"])
