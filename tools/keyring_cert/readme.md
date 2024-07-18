# Keyring Cert-Gen tool {#TOOLS_KEYRING_CERT_GEN}

\note Support for encryption with symmetric auxiliary keys will be added in future releases.

# Description:
- This script is used to generate X.509 certificate for keyring.
- Make sure that python3 and its dependent modules are installed in the host machine.
- keyring_cert_gen.py parses json object containing the following meta-data for keyring cert generation:
    - keyring_sw_rev: This integer value is used for anti-rollback check against the keyring software revision available in device efuses.
    - keyring_ver: Keyring version is of type integer and is the version which is supported against the TIFS-MCU version being used in HSM.
    - num_of_asymm_keys: Number of Asymmetric keys being imported.
    - num_of_symm_keys: Number of Symmetric keys being imported.
    - keyring_asymm: Array of asymmetric keys with respective key rights and hash algorithm to compute and store the hash of the public key.

\imageStyle{keyring_tooling_view.png,width:50%}
\image html keyring_tooling_view.png "Keyring certificate generation and import"

\code
{
    "keyring_sw_rev" : 1,
    "keyring_ver" : 1,
    "num_of_asymm_keys" : 7,
    "num_of_symm_keys" : 0,
    "keyring_asymm" :  [
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/public2k.pem",
                    "hash_algo": "SHA256"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/public3k.pem",
                    "hash_algo" : "SHA512"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/public4k.pem",
                    "hash_algo" : "SHA512"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/prime265v1_public.pem",
                    "hash_algo" : "SHA512"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/secp384r1_public.pem",
                    "hash_algo" : "SHA512"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/secp521r1_public.pem",
                    "hash_algo" : "SHA384"
                },
                {
                    "key_rights": "000000AA",
                    "pub_key": "aux_keys/brainpoolp512r1_public.pem",
                    "hash_algo" : "SHA384"
                }
      ],
    "keyring_symm" :  []
}

\endcode
- Each asymmetric key json object contain 3 fields:
    - key_rights: Integer value in HEX format which signifies the rights associated with the key.
        - debugAuth (0-3b) - flag to indicate key right for debug certificate authentication
        - imageAuth (4-7b) - flag to indicate key right for application image authentication
        - For example: 0x000000AA represents the public key hash can be used for both imageAuth and debugAuth
    - pub_key: Location of the public key
    - hash_algo: Hash algorithm used for hashing public key.
        - SHA256, SHA384 and SHA512 are valid hash algorithms.
- keyring_cert_gen.py expects 2 mandatory arguments:
    - root_key: certificate is signed using customer MPK and expects path to customer active ROT.
    - keys_info: json file with keyring meta data.
- A dummy json and keyring certificate header file is also availble in ${TIFS_INSTALL_PATH}/tools/keyring_cert for reference.
- Below are the logs after execution of script
    \code
keyring version = 1
keyring software revision = 1
Number of asymmetric keys = 7
Number of symmetric keys = 0

[ keyring_asymm ]
asymm_key0=SEQUENCE:comp0
asymm_key1=SEQUENCE:comp1
asymm_key2=SEQUENCE:comp2
asymm_key3=SEQUENCE:comp3
asymm_key4=SEQUENCE:comp4
asymm_key5=SEQUENCE:comp5
asymm_key6=SEQUENCE:comp6

[ comp0 ]
keyId=INTEGER:32
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:6
public_key=FORMAT:HEX,OCT:582fc2a6cc997d2df6c0299aeef0a7b606d3fcc2261dfade8c2684c6663ab50b

[ comp1 ]
keyId=INTEGER:33
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:4
public_key=FORMAT:HEX,OCT:6e430c4a09572240f9acd4b4777b2d662fe28c73ef475280d8a4e7c766d13680b14549a84e6e6c7b69a0ba33840dc9f51f110afb156251a6139c26693e6d4ddf

[ comp2 ]
keyId=INTEGER:34
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:4
public_key=FORMAT:HEX,OCT:67cd4b91e7966af635a53642102abb2c8fdab1a47277c88eb4ec3e1a6ce5155a2325f66b3d392f3f5091e526057cd5e6b6d5085ae46f169c61de77c7dffbb238

[ comp3 ]
keyId=INTEGER:35
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:4
public_key=FORMAT:HEX,OCT:79bd183d942cbf1542a2bad2a469242392c515c1546fc8a43e86a024097ba4bb4db65ccade7fb6b252deccd255491151df927f998d468153072cf3e4949d6002

[ comp4 ]
keyId=INTEGER:36
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:4
public_key=FORMAT:HEX,OCT:4a8959978336886acbe3cf294b1b8e1aa68f1cb836d78aa11332a57cb44c435c82fc672901a2a242e5169543502106ac0cda1b04a9769723154d640e832298ba

[ comp5 ]
keyId=INTEGER:37
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:2
public_key=FORMAT:HEX,OCT:1b759f0c0b04796cc599033bd58e33730ce6b2380f7442fe030beffa3cc844ce0d196f48e5ebeb6d88eea0f7ddc3beb7

[ comp6 ]
keyId=INTEGER:38
key_rights=FORMAT:HEX,OCT:000000AA
hash_algo=INTEGER:2
public_key=FORMAT:HEX,OCT:b502e951a5f5ed4bc99191511b530597d3a2d356d0f83887a54253a7ec46fb2c081c7d39391f846932357a57133f8c11
\endcode


## Argument Options -
    - 'root_key'     : This is a mandatory parameter which is required to give
                       the key value required to sign the certificate. Key
                       file name with path required.
    - 'keys_info'    : This is a mandatory parameter which is required to give
                       the json file which contains the keyring data for certificate creation.
    - rsassa_pss     : This is an optional parameter which is used if RSASSA-PSS 
                       algorithm is used for keyring certificate authentication.
    - pss_saltlen    : This is an optional parameter which is used to provide salt 
                       length if RSASSA-PSS algorithm is used for keyring certificate 
                       authentication.

## Example Use -
\code
python3 keyring_cert_gen.py  --root_key ../boot/signing/mcu_custMpk.pem --keys_info keys.json
\endcode

If RSASSA-PSS algorithm for authentication of keyring certificate is required, provide the --rsassa_pss flag and --pss_saltlen **value**. Maximum supported salt length value for RSASSA-PSS is **255**. Please refer to the command below
\code
$python3 keyring_cert_gen.py --root_key ../boot/signing/mcu_custMpk.pem --keys_info keys.json --rsassa_pss --pss_saltlen 64
\endcode
