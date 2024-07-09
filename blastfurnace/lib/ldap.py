from binascii import hexlify
import base64
import logging
import typing
import uuid
from impacket.ldap import ldap, ldapasn1
from impacket.ldap.ldaptypes import LDAP_SID
from impacket.examples.utils import parse_credentials
from blastfurnace.lib.dpapi import KeyCache
from blastfurnace.lib.dpapi import KeyIdentifier

logger = logging.getLogger(__name__)

class LdapSession:

    def __init__(self, options):
        self.domain, self.username, self.password = parse_credentials(options.target)
        self.lmhash = ""
        self.nthash = ""
        self.target = ""
        self.aes_key = options.aes_key
        self.do_kerberos = options.k
        self.kdc_ip = options.dc_ip
        self.kdc_host = options.dc_host
        self.hashes = options.hashes
        if options.hashes is not None:
            self.lmhash, self.nthash = options.hashes.split(":")

        domain_parts = self.domain.split(".")
        self.base_dn = ""
        for i in domain_parts:
            self.base_dn += f"DC={i},"
        # remove trailing comma
        self.base_dn = self.base_dn[:-1]

        # create an empty KeyCache for processing
        self.cache = KeyCache()

        # empty dictionary to hold gMSA accounts as KeyIdentities
        self.key_identifiers = {}

    def _process_gmsa_record(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return

        gmsa_sid = b""
        mskds_managed_password_id = b""
        sam_name = ""

        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == "msDS-ManagedPasswordId":
                    mskds_managed_password_id = attribute['vals'][0].asOctets()
                    logger.debug(f"[-] msKds-ManagedPasswordID={base64.b64encode(mskds_managed_password_id).decode()}")
                elif str(attribute['type']) == "objectSid":
                    gmsa_sid = attribute['vals'][0].asOctets()
                    logger.debug(f"[-] gmsa_sid={base64.b64encode(gmsa_sid).decode()}")
                elif str(attribute['type']) == "sAMAccountName":
                    sam_name = attribute['vals'][0].asOctets().decode()
                    logger.debug(f"[-] SAM account name={sam_name}")
        except Exception as e:
            logger.debug("[-] Exception", exec_info=True)
            logger.error(f"[!] Skipping item, cannot process due to error {e}")
            pass

        sid = LDAP_SID(gmsa_sid)
        key_id = KeyIdentifier.unpack(mskds_managed_password_id)
        self.key_identifiers[sid] = {}
        self.key_identifiers[sid]["keyid"] = key_id
        self.key_identifiers[sid]["sam"] = sam_name

    def _process_kds_root_record(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return

        mskds_root_key_data = b""
        mskds_version = 0
        mskds_kdf_param = b""
    
        try:
            for attribute in item['attributes']:
                if str(attribute['type']) == 'cn':
                    root_id_str = attribute['vals'][0].asOctets().decode('utf-8')
                    logger.debug(f"[-] rootID={root_id_str}")
                elif str(attribute['type']) == "msKds-Version":
                    mskds_version = int(attribute['vals'][0])
                    logger.debug(f"[-] msKds-Version={mskds_version}")
                elif str(attribute['type']) == "msKds-KDFAlgorithmID":
                    mskds_kdf_algorithm_id = attribute['vals'][0].asOctets().decode('utf-8')
                    logger.debug(f"[-] msKds-KDFAlogrithmID={mskds_kdf_algorithm_id}")
                elif str(attribute['type']) == "msKds-KDFParam":
                    mskds_kdf_param = attribute['vals'][0].asOctets()
                    logger.debug(f"[-] msKds-KDFParam={hexlify(mskds_kdf_param).decode()}")
                # TODO possibly debug print the UseStartTime
                #elif str(attribute['type']) == "msKds-UseStartTime":
                #    mskds_use_start_time = int(attribute['vals'][0])
                #    logger.debug(f"msKds-UseStartTime={mskds_use_start_time}")
                elif str(attribute['type']) == "msKds-RootKeyData":
                    mskds_root_key_data = attribute['vals'][0].asOctets()
                    logger.debug(f"[-] mskds-root_key_data={hexlify(mskds_root_key_data).decode()}")
        except Exception as e:
            logger.debug("[-] Exception", exec_info=True)
            logger.error(f"[!] Skipping item, cannot process due to error {e}")
            pass
      
        # store KDS root key in cache
        root_id = uuid.UUID(root_id_str)
        self.cache.load_key(mskds_root_key_data,
                            root_id, version=mskds_version, kdf_algorithm=mskds_kdf_algorithm_id,
                            kdf_parameters=mskds_kdf_param)
        logger.info(f"[+] retrieved root key {root_id_str}")

    def get_kds_root_keys(self):

        requested_base = "CN=Configuration," + self.base_dn

        self._ldap_login(requested_base)
        logger.info(f"[>] Querying {self.target} for KDS Root Parameters")

        # build search filter
        search_filter = "(&(objectClass=msKds-ProvRootKey))"

        try:
            logger.debug(f"[-] Search filter={search_filter}")
            sc = ldap.SimplePagedResultsControl(size=1)
            self.ldapConnection.search(searchFilter=search_filter,
                searchControls = [sc], perRecordCallback=self._process_kds_root_record)
        except ldap.LDAPSearchError:
            raise

        self.ldapConnection.close()

        return self.cache

    def get_gmsa_params(self):

        logger.info("[>] Querying for gMSA accounts")
        self._ldap_login(self.base_dn)

        search_filter = "(&(ObjectClass=msDS-GroupManagedServiceAccount))"

        try:
            logger.debug(f"[-] search filter={search_filter}")
            sc = ldap.SimplePagedResultsControl(size=1)
            self.ldapConnection.search(searchFilter=search_filter,
                searchControls = [sc], perRecordCallback=self._process_gmsa_record)
        except ldap.LDAPSearchError:
            raise

        self.ldapConnection.close()

        return self.key_identifiers
      
    def _ldap_login(self, requested_base):
      
        if self.domain == '':
            logger.critical('[!] Domain should be specified!')
            sys.exit(1)
      
        if self.password == '' and self.username != '' and self.hashes is None and self.no_pass is False and self.aes_key is None:
            from getpass import getpass
            self.password = getpass("Password:")

        if self.aes_key is not None:
            self.k = True

        if self.kdc_host is not None:
            self.target = self.kdc_host
        else:
            if self.kdc_ip is not None:
                self.target = self.kdc_ip
            else:
                self.target = self.domain

        try:
            self.ldapConnection = ldap.LDAPConnection(f"ldap://{self.target}", requested_base, self.kdc_ip)
            if self.do_kerberos is not True:
                self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
            else:
                self.ldapConnection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash,
                                             self.aes_key, kdcHost=self.kdc_ip)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # try ldaps instead
                self.ldapConnection = ldap.LDAPConnection(f"ldaps://{self.target}", requested_base, self.kdc_ip)
                if self.do_kerberos is not True:
                    self.ldapConnection.login(self.username, self.password, self.domain, self.lmhash, self.nthash)
                else:
                    self.ldapConnection.kerberosLogin(self.username, self.password, self.domain, self.lmhash, self.nthash,
                                                 self.aes_key, kdcHost=self.kdc_ip)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logger.critical("[!] NTLM negotiation failed. Probably NTLM is disabled. Try to use kerberos auth instead")
                else:
                    if self.kdc_ip is not None:
                        logger.critical("[!] If the creds are valid, check the hostname and IP address of the KDC. They must match")
            raise

        logger.debug("[-] Connected to the LDAP server")
        return self.ldapConnection

