from binascii import hexlify
from Cryptodome.Hash import MD4
from passlib.hash import lmhash
from impacket.krb5 import constants
from impacket.krb5.crypto import string_to_key

def calculate_ntlm_hash(passwd, sam_name, domain):
    password = passwd.decode('utf-16-le', 'replace').encode('utf-8')
    lmpass = lmhash.hash(password)
    ntlm_hash = MD4.new ()
    ntlm_hash.update (passwd)
    ntlm_pass = hexlify(ntlm_hash.digest()).decode("utf-8")
    full_hash = lmpass + ":" + ntlm_pass

    return full_hash

def calculate_aes_passwd(passwd, sam_name, domain):
    password = passwd.decode('utf-16-le', 'replace').encode('utf-8')
    salt = '%shost%s.%s' % (domain.upper(), sam_name[:-1].lower(), domain.lower())
    aes_128_hash = hexlify(string_to_key(constants.EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt).contents)
    aes_256_hash = hexlify(string_to_key(constants.EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt).contents)
    aes_128 = aes_128_hash.decode('utf-8')
    aes_256 = aes_256_hash.decode('utf-8')
    return aes_128, aes_256

#print('%s:aes256-cts-hmac-sha1-96:%s' % (sam, aes_256_hash.decode('utf-8')))
#print('%s:aes128-cts-hmac-sha1-96:%s' % (sam, aes_128_hash.decode('utf-8')))
