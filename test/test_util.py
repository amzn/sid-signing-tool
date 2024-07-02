# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import unittest
from binascii import hexlify

from sid_signing_tool import util
from sid_signing_tool.types import STAGE


class TestUtilities(unittest.TestCase):
    def test_smsn_generator(self):
        smsn = util.generate_smsn(STAGE.PROD, "DUMMY", "FAKE_APID", "FAKE_DSN")
        self.assertEqual(
            str(hexlify(smsn), "ascii"),
            "1f4ee02cd76fed7f9f30b02169e582f6685970c76d33b48b7951dd5a555b7ec6",
        )

    def test_stage2str(self):
        self.assertEqual(util.stage2str(STAGE.PROD), "PRODUCTION")
        self.assertEqual(util.stage2str(STAGE.PREPROD), "PREPRODUCTION")
        self.assertEqual(util.stage2str(STAGE.TEST), "TEST")
