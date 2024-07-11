import argparse

from blastfurnace.commands.offline import execute_offline
from blastfurnace.commands.auto_command import execute_auto

banner = '''
█▄▄ █░░ ▄▀█ █▀ ▀█▀ █▀▀ █░█ █▀█ █▄░█ ▄▀█ █▀▀ █▀▀
█▄█ █▄▄ █▀█ ▄█ ░█░ █▀░ █▄█ █▀▄ █░▀█ █▀█ █▄▄ ██▄
'''

def parse_commandline():

    p = argparse.ArgumentParser("BlastFurnace", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner + "A refinement on the Golden gMSA attack tool")
    subparsers = p.add_subparsers(title="commands", required=True, metavar="")
    auto = subparsers.add_parser("auto", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner, help="run command in full auto mode")
    auto.add_argument("account", action="store", help="domain[/username[:password]]")
    auto.add_argument("-kcache", default="root_keys.kcache",
        help="Specify kcache filename to save KDS root key(s)")
    auto.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    auto_group = auto.add_argument_group("authentication")
    auto_group.add_argument("-hashes", action="store", metavar = "LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH")
    auto_group.add_argument("-no-pass", action="store_true", 
        help="don't ask for password (used with -k)")
    auto_group.add_argument("-k", action="store_true",
        help="Use kerberos authentication. Grabs creds from ccache file")
    auto_group.add_argument("-aeskey", dest="aes_key", action="store", metavar= "aes",
        help="AES key to use for Kerberos Authentication. 128 or 256 bits")

    auto_group = auto.add_argument_group("connection")
    auto_group.add_argument("-dc-ip", action="store", metavar="dc_ip",
        help="IP Address of domain controller.")
    auto_group.add_argument("-dc-host", action="store", metavar="dc_host",
        help="Hostname of domain controller.")

    auto_group = auto.add_argument_group("msKds-ManagedPasswordId")
    auto_group.add_argument("-gmsa",
        help="Specify a target gMSA by account name")
    auto.set_defaults(execute=execute_auto)

    offline = subparsers.add_parser("offline",
        formatter_class=argparse.RawDescriptionHelpFormatter, description=banner,
        help="offline mode, all material required")
    offline.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")
    gmsa_details = offline.add_argument_group(title="gMSA Info")
    gmsa_details.add_argument("-sam", metavar="SAM",
        help="SAM account name")
    gmsa_details.add_argument("-mpid", metavar="MPID",
        help="msDs-ManagedPasswordId in base64 format")
    gmsa_details.add_argument("-sid", metavar="SID",
        help="objectSID in base64 format")

    kds_details = offline.add_argument_group(title="KDS Root Key Info",
        description="Provide either the KDS Cache file or the msKds attributes")
    kds_details.add_argument("-key",
        help="msKds-RootKeyData in base64 format")
    kds_details.add_argument("-kdfparam",
        help="msKds-KDFParam in base64 format")
    kds_details.add_argument("-rkid",
        help="msKds-ProvRootKey CN in UUID format")
    kds_details.add_argument("-kcache",
        help="KDS Cache file (.kcache) containing KDS Root Key information")
    offline.set_defaults(execute=execute_offline)

    #return p.parse_args()
    return p
