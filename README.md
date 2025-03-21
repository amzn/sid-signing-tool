# Sidewalk Signing Tool
Please refer to the Sidewalk Manufacturing Guide.

# Companion utilities for signing and provisioning
There are 2 utilities to help with signing operations.

## Extract private key in hexadecimal format from a PEM key file

To work with provisioning.py, the private keys for ECDSA and
EDDSA need to be filled up in the JSON file no matter manually or
automatically from the signing tool. This tool helps to extract the key data
from the PEM files (if the private keys are generated with OpenSSL or
similar tools) and convert it to hexadecimals that is suitable for the JSON
file.

```
$ python3 extract_priv.py testp256r1.pem
bc25e2a273d5340f5481615c206d9b5e8aa7ab0f11de0d5810b0dfc7f7e18166
```

## Validate the Sidewalk certificate chain

Once the Sidewalk certificate chain is generated by the signing tool, this
tool could be used for listing the certificates inside the chain and then
validating them. It makes sure each level of certificate can be validated
with its issuer or is self-signed if it's a root certificate.

```
$ python3 validate_chain.py JNTwXmILBd2ODPSSedYVApPAGe3L106QZ0O1h7wfHTUKYxUkbsfdzOECzOBCSTKyCoqF2+mTIX99lXVbETobCtc37/DMHFP2AWgGH0OHegrTd4AyjVB9xhhFqUeJNsQhUM2bbxtwh7nQKKJOjuDbw2T0BoUQaupg6SuQo2cRmgwBHAD6Fc/FAIWYJ7yFKcbwLE4gdihuA1QvGzcxqbqHTJDSI/Yabdz0pQKIJuz0mrHA5qAHogcPz2lvqERJqXuTKxavUR6Cqnt4G4AVxUAaZbKwJypUzGbOkXvuABm+/Nu1GHQAAOUAeOvZnM7+/x5b6xDnknjdjeHgLtMFbKcqjri59LDbhZM2LCUd0Z9Yce2wahqYja+4hdEqq61aAYGWDZjzs5Jf9KPuUQakAvNA8qNJTOKAcYL/rh+7G63iCR9KW5t0gt+1AQDYAHzSO0Dw/C+YOxINIP2tbWOjE3SP4W/aO9sVphTD0IuEWzgiXASwC3a3AGKZWIo2vgP4ASDRTTwT0P8AgVxc2kAbSlw4y/QxIA1zDZvO8dx+DgjC1/xchftBOaO8YpwvxwJ1AAADGz+gFBeX/ZNN8VJwnsNfgzj4me1HgVJdUo4W9kvx9cr2jHWkC3Oj/bdBTh1+yBjOC53yHlQK/l1GHrEWiWPPnE434LRxnWkwr8EHD4oieJxC8fkIxkQfj+gHhU79Z+oAAYAAAzsnf9SDIZPoDXF0TdC9POqTgld0oXDl2XPaVD4CvvLearrOSlFv+lsNbC4rgZn23MtIBM/7YQmJwmQ+FXRup6Tkubg1hpz04J/09dxg8UiZmntHiUr1GfkTOFMYqRB+Aw==
[0] CA_TYPE.DEVICE:
  Serial   : 24d4f05e620b05dd8e0cf49279d6150293c019edcbd74e906743b587bc1f1d35
  Pubk     : 0a6315246ec7ddcce102cce0424932b20a8a85dbe993217f7d95755b113a1b0a
  Signature: d737eff0cc1c53f60168061f43877a0ad37780328d507dc61845a9478936c42150cd9b6f1b7087b9d028a24e8ee0dbc364f40685106aea60e92b90a367119a0c
[1] CA_TYPE.DAK:
  Serial   : 011c00fa
  Pubk     : 15cfc500859827bc8529c6f02c4e2076286e03542f1b3731a9ba874c90d223f6
  Signature: 1a6ddcf4a5028826ecf49ab1c0e6a007a2070fcf696fa84449a97b932b16af511e82aa7b781b8015c5401a65b2b0272a54cc66ce917bee0019befcdbb5187400
[2] CA_TYPE.PROD:
  Serial   : 00e50078
  Pubk     : ebd99ccefeff1e5beb10e79278dd8de1e02ed3056ca72a8eb8b9f4b0db859336
  Signature: 2c251dd19f5871edb06a1a988dafb885d12aabad5a0181960d98f3b3925ff4a3ee5106a402f340f2a3494ce2807182ffae1fbb1bade2091f4a5b9b7482dfb501
[3] CA_TYPE.MANU:
  Serial   : 00d8007c
  Pubk     : d23b40f0fc2f983b120d20fdad6d63a313748fe16fda3bdb15a614c3d08b845b
  Signature: 38225c04b00b76b7006299588a36be03f80120d14d3c13d0ff00815c5cda401b4a5c38cbf431200d730d9bcef1dc7e0e08c2d7fc5c85fb4139a3bc629c2fc702
[4] CA_TYPE.SIDEWALK:
  Serial   : 75000003
  Pubk     : 1b3fa0141797fd934df152709ec35f8338f899ed4781525d528e16f64bf1f5ca
  Signature: f68c75a40b73a3fdb7414e1d7ec818ce0b9df21e540afe5d461eb1168963cf9c4e37e0b4719d6930afc1070f8a22789c42f1f908c6441f8fe807854efd67ea00
[5] CA_TYPE.AMZN:
  Serial   : 01800003
  Pubk     : 3b277fd4832193e80d71744dd0bd3cea93825774a170e5d973da543e02bef2de
  Signature: 6abace4a516ffa5b0d6c2e2b8199f6dccb4804cffb610989c2643e15746ea7a4e4b9b835869cf4e09ff4f5dc60f148999a7b47894af519f913385318a9107e03
Pass: the certificate chain of CURVE.ED25519 is valid
```

## Consolidate multiple control logs

As the signing tool could generate control logs for a single device that it processes,
it is convenient and efficient to do WCL ingestion with a control log file containing
information of multiple devices. This tool is to consolidate multiple control logs
which have one device in each to form a single control log file.

This tool reads control log files from argument list and generate a big one whose
name will be printed out on the last line of standard output.

```
$ python3 consolidate_cl.py /tmp/cl/C_CONTROL_LOG_*.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018122452.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141057.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141105.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141106.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141108.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141109.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141110.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141112.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141113.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141115.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141116.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141123.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141124.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141126.txt
Processing /tmp/cl/C_CONTROL_LOG_20221018141421.txt
C_CONTROL_LOG_20221018152806.txt
$
```

