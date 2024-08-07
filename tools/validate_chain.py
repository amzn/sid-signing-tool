# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import base64
import sys

from sid_signing_tool.cert import SidewalkCertChain
from sid_signing_tool.types import CURVE


# As we have variable length of sn, there's no way to know the type of the chain
def try_with_curves(chain):
    try:
        return SidewalkCertChain.from_raw(chain, CURVE.ED25519)
    except ValueError:
        pass
    return SidewalkCertChain.from_raw(chain, CURVE.P256R1)


if len(sys.argv) != 2:
    sys.exit("Usage: %s CERT_CHAIN_IN_BASE64" % sys.argv[0])
chain = base64.standard_b64decode(sys.argv[1])

try:
    sidewalk_chain = try_with_curves(chain)
except ValueError:
    raise Exception("Unable to parse the chain")

i = 0
for cert in reversed(sidewalk_chain):
    print("[%d] %s:" % (i, cert.type.name))
    print("  Serial   : %s" % cert.serial.hex())
    print("  Pubk     : %s" % cert.pubk.hex())
    print("  Signature: %s" % cert.signature.hex())
    i = i + 1

try:
    sidewalk_chain.validate()
    print("Pass: the certificate chain of %s is valid" % sidewalk_chain[0].curve.name)
except:
    pass
