# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0


class MissingCertificateObject(Exception):
    pass


class InvalidCSRLength(Exception):
    pass


class InvalidEddsaCSR(Exception):
    pass


class InvalidEcdsaCSR(Exception):
    pass
