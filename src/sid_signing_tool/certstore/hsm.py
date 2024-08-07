# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

import binascii
import json
import logging
import os
import ssl
import tempfile

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
    encode_dss_signature,
)
from packaging import version
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
from yubihsm import YubiHsm
from yubihsm.backends.http import HttpBackend
from yubihsm.defs import ALGORITHM, CAPABILITY, ERROR, OBJECT
from yubihsm.exceptions import (
    YubiHsmAuthenticationError,
    YubiHsmConnectionError,
    YubiHsmDeviceError,
)
from yubihsm.objects import AsymmetricKey, ObjectInfo

from sid_signing_tool import exceptions
from sid_signing_tool.cert import SidewalkCert, SidewalkCertChain
from sid_signing_tool.types import CATYPE, CURVE, ELEMENT, NAMESPACE, STAGE

SIDEWALK_AUTH_KEY_INDEX = 5
SIDEWALK_AUTH_KEY_INDEX_PREPROD = 6
CHAIN_DEPTH_CTL_LABEL = "SW_CTL_CHAIN_DEPTH"
HSM_INFO_LABEL = "HSM_INFO"

logger = logging.getLogger(__name__)


class Object:
    def __init__(self, instance):
        self._instance = instance
        self._info = None
        self._content = None

    @property
    def id(self):
        return self._instance.id

    @property
    def type(self):
        return self._instance.object_type

    @property
    def info(self):
        if self._info is None:
            logger.debug("Getting info for object 0x%x on HSM" % self.id)
            self._info = self._instance.get_info()
        return self._info

    @property
    def content(self):
        if self._content is None:
            logger.debug("Getting content for object 0x%x on HSM" % self.id)
            self._content = self._instance.get()
        return self._content

    @property
    def namespace(self):
        return self._instance.id // 0x10 * 0x10

    @property
    def tag(self):
        return "0x%04x-%s" % (self.id, self.type)


class HsmCertStore:
    def __init__(
        self,
        connector,
        pin,
        stage,
        signer_tag,
        pin_slot=None,
        enable_cache=False,
        ca_cert=None,
        client_cert=None,
        client_key=None,
    ):
        self._connector = connector
        self._signer_tag = signer_tag
        self._pin = pin
        self._pin_slot = pin_slot
        self._stage = stage
        self._enable_cache = enable_cache
        self._cache = None

        # Set up certs for TLS
        def init_wrapper(init_func, ca, client_cert, client_key):
            class Tls12HttpAdapter(HTTPAdapter):
                """ "Use TLSv1.2"""

                def init_poolmanager(self, connections, maxsize, block=False):
                    self.poolmanager = PoolManager(
                        num_pools=connections,
                        maxsize=maxsize,
                        block=block,
                        ssl_version=ssl.PROTOCOL_TLSv1_2,
                    )

            def init_with_certs(*args, **kwargs):
                init_func(*args, **kwargs)

                if ca is not None:
                    args[0]._session.verify = ca
                if client_cert is not None:
                    args[0]._session.cert = (client_cert, client_key)
                args[0]._session.mount("https://", Tls12HttpAdapter())

            return init_with_certs

        if ca_cert is not None or client_cert is not None:
            HttpBackend.__init__ = init_wrapper(
                HttpBackend.__init__, ca_cert, client_cert, client_key
            )

    def open(self):
        self._hsm = YubiHsm.connect(self._connector)
        self._session = self.create_hsm_session(self._hsm, self._pin, self._pin_slot, self._stage)
        self._cache_file = os.path.join(
            tempfile.gettempdir(),
            "signing-tool-" + str(self._hsm.get_device_info().serial) + ".tmp",
        )

        if self._enable_cache:
            logger.info("Loading cache at " + self._cache_file)
            try:
                with open(self._cache_file, "r") as f:
                    self._cache = json.loads(f.read())
            except (FileNotFoundError, json.decoder.JSONDecodeError):
                pass
        else:
            try:
                os.remove(self._cache_file)
            except FileNotFoundError:
                pass

        # Construct basic map of HSM

        logger.info("Listing objects on HSM")
        self.objects = [Object(o) for o in self._session.list_objects()]

        if self._cache:
            for object in self.objects:
                tag = object.tag
                try:
                    object._info = ObjectInfo(*self._cache[tag]["info"])
                    object._content = bytes.fromhex(self._cache[tag]["content"])
                except KeyError as e:
                    pass

        hsm_info_obj = self.search_for(lambda o: o.id < 0x10 and o.info.label == HSM_INFO_LABEL)
        if hsm_info_obj:
            hsm_info = json.loads(hsm_info_obj.content)
            logger.info("Found HSM INFO: %s" % hsm_info)
            self._toolreq = hsm_info["toolreq"]
            self._legacy_chain = not hsm_info["longchain"]
        else:
            chain_depth_control = self.search_for(
                lambda o: o.id < 0x10 and o.info.label == CHAIN_DEPTH_CTL_LABEL
            )

            if chain_depth_control is None:
                self._legacy_chain = True
            else:
                chain_depth = int.from_bytes(chain_depth_control.content, "little")
                if chain_depth != 5:
                    # Sidewalk currently only uses 5-depth chain
                    raise Exception("Unsupported chain depth " + str(chain_depth) + " found in HSM")
                self._legacy_chain = False

        signer = self.search_for(
            lambda o: o.type == OBJECT.ASYMMETRIC_KEY and o.info.label.startswith(self._signer_tag)
        )

        if signer is None:
            raise Exception("Can't find the Signer with " + self._signer_tag)

        logger.info("Found signer at namespace=0x%x", signer.namespace)

        if self._legacy_chain:
            self._namespace_def = {
                CATYPE.AMZN: NAMESPACE.AMAZON,
                CATYPE.MAN: NAMESPACE.MAN_LEGACY,
                CATYPE.MODEL: signer.namespace,
            }
        else:
            prod_tag = self._signer_tag.replace("_DAK", "_PROD")
            if self._signer_tag == prod_tag:
                raise ValueError("The tag for the DAK doesn't contain the mark 'DAK'")

            # To reduce number of searchs, just check the object for ELEMENT.PUBK
            serial_index_offset = signer.id - signer.namespace - ELEMENT.PRIV + ELEMENT.PUBK

            for namespace in range(NAMESPACE.CERT_START, NAMESPACE.CERT_END, 0x10):
                id = namespace + serial_index_offset
                logger.info("Searching in id 0x%x for %s" % (id, prod_tag))
                prod_pubk = self.search_for_id_and_type(id, OBJECT.OPAQUE)
                if prod_pubk and prod_pubk.info.label.startswith(prod_tag):
                    break
                prod_pubk = None

            if prod_pubk is None:
                raise Exception("Can't find corresponding product cert for " + self._signer_tag)

            logger.info("Found prod ca at namespace=0x%x", prod_pubk.namespace)

            self._namespace_def = {
                CATYPE.AMZN: NAMESPACE.AMAZON,
                CATYPE.SIDEWALK: NAMESPACE.SIDEWALK,
                CATYPE.MAN: NAMESPACE.MAN,
                CATYPE.PROD: prod_pubk.namespace,
                CATYPE.DAK: signer.namespace,
            }

    def close(self):
        if self._enable_cache and self._cache is None:
            with open(self._cache_file, "w") as f:
                f.write(self.dump())
        self._session.close()
        self._hsm.close()

    def create_hsm_session(self, hsm, pin, pin_slot, stage):
        try_slots = [SIDEWALK_AUTH_KEY_INDEX, SIDEWALK_AUTH_KEY_INDEX_PREPROD]
        if stage == STAGE.PREPROD:
            try_slots = [SIDEWALK_AUTH_KEY_INDEX_PREPROD, SIDEWALK_AUTH_KEY_INDEX]
        if pin_slot:
            try_slots = [pin_slot]

        for slot in try_slots:
            try:
                logger.debug("Authenticating with key slot %d" % slot)
                return hsm.create_session_derived(slot, pin)
            except YubiHsmDeviceError as e:
                if e.code != ERROR.OBJECT_NOT_FOUND:
                    raise e
        raise Exception("No key slot found for authentication")

    def search_for(self, func):
        for object in self.objects:
            if func(object):
                return object
        return None

    def search_for_id_and_type(self, id, objectype):
        return self.search_for(lambda o: o.id == id and o.type == objectype)

    def construct_id_from(self, namespace, curve, stage, element):
        index = namespace
        index += curve << 3
        # PRODUCTION use the top half of a curve's space while the others use the bottom half
        index += 4 if stage != STAGE.PROD else 0
        index += element
        return index

    def sign(self, curve, data):
        signer_type = CATYPE.DAK if not self._legacy_chain else CATYPE.MODEL
        signer_namespace = self._namespace_def[signer_type]
        signer_id = self.construct_id_from(signer_namespace, curve, self._stage, ELEMENT.PRIV)
        signer_object = self.search_for_id_and_type(signer_id, OBJECT.ASYMMETRIC_KEY)
        if signer_object is None:
            raise Exception("Can't find the signer")

        if curve == CURVE.ED25519:
            logger.debug("Signing eddsa with 0x%x on HSM" % signer_object.id)
            return signer_object._instance.sign_eddsa(data)
        elif curve == CURVE.P256R1:
            hasher = hashes.Hash(hashes.SHA256())
            hasher.update(data)
            digest = hasher.finalize()
            logger.debug("Signing ecdsa with 0x%x on HSM" % signer_object.id)
            sig_in_der = signer_object._instance.sign_ecdsa(data)
            # YubiHSM's ecdsa signature is encoded in DER
            (r, s) = decode_dss_signature(sig_in_der)
            return r.to_bytes(32, byteorder="big") + s.to_bytes(32, byteorder="big")

    def get_certificate(self, type, curve):
        namespace = self._namespace_def[type]
        cert_data = {}
        for e in ELEMENT:
            if e == ELEMENT.PRIV:
                continue
            id = self.construct_id_from(namespace, curve, self._stage, e)

            logger.debug("Getting cert obj on 0x%x for %s" % (id, e))
            object = self.search_for_id_and_type(id, OBJECT.OPAQUE)

            if object is None:
                raise exceptions.MissingCertificateObject(
                    "missing certificate object for %s at 0x%x" % (e, id)
                )
            cert_data[e] = object.content

        return SidewalkCert(
            type=type,
            curve=curve,
            serial=cert_data[ELEMENT.SERIAL],
            signature=cert_data[ELEMENT.SIGNATURE],
            pubk=cert_data[ELEMENT.PUBK],
        )

    def get_certificate_chain(self, curve):
        chain = SidewalkCertChain()
        for cert_type, namespace in sorted(self._namespace_def.items()):
            logger.debug(f"Getting cert for {cert_type!r}")
            chain.append(self.get_certificate(cert_type, curve))
        return chain

    def dump(self):
        t = {}
        for object in self.objects:
            tag = object.tag
            t[tag] = {"id": object.id, "type": object.type, "info": object.info}
            if object.type == OBJECT.OPAQUE:
                t[tag]["content"] = str(binascii.hexlify(object.content), "ascii")
        return json.dumps(t, indent=4)
