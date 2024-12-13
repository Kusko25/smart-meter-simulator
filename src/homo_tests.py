from openfhe import *

parameters = CCParamsBGVRNS()
parameters.SetPlaintextModulus(65537)

# NOISE_FLOODING_MULTIPARTY adds extra noise to the ciphertext before decrypting
# and is most secure mode of threshold FHE for BFV and BGV.
parameters.SetMultipartyMode(NOISE_FLOODING_MULTIPARTY)

cc = GenCryptoContext(parameters)
# Enable Features you wish to use
cc.Enable(PKE)
cc.Enable(KEYSWITCH)
cc.Enable(LEVELEDSHE)
cc.Enable(ADVANCEDSHE)
cc.Enable(MULTIPARTY)

package = {
    "a": 212,
    "cc": cc
}
print(b"b"*package.__sizeof__())