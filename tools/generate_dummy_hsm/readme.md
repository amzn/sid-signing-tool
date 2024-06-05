# Generating a dummy HSM
Before the official HSM is arrived, one can use this tool to program the dummy Sidewalk certificate chain to a blank HSM for early testing

# Pre-requisites
- yubihsm-connector
- Python3
- And install dependencies
```
pip3 install -r requirements.txt
```

# Usage

1. Run yubihsm-connector
2. Prepare a blank HSM
3. Run generate_dummy_hsm.py with the cert chain file provided

```
m$ python3 ./generate_dummy_hsm.py
Completed the programming of dummy keys for RNET_DAK_DUMMY with PIN=1234
```

# Note
- The HSM to be programmed must be totally blank. How to reset a HSM: https://developers.yubico.com/YubiHSM2/Usage_Guides/Factory_reset.html
- Product tag and the PIN for the generated HSM are RNET_DAK_DUMMY and 1234 by default, which are customizable
(see the help) and necessary for signing tool's testing
