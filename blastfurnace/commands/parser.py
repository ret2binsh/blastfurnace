import argparse

from blastfurnace.commands.auto_command import execute_auto
from blastfurnace.commands.generate_command import execute_generate

banner = '''
█▄▄ █░░ ▄▀█ █▀ ▀█▀ █▀▀ █░█ █▀█ █▄░█ ▄▀█ █▀▀ █▀▀
█▄█ █▄▄ █▀█ ▄█ ░█░ █▀░ █▄█ █▀▄ █░▀█ █▀█ █▄▄ ██▄'''

def generate_password(args):
    print(f"generate args: {args}")

def parse_commandline():

    p = argparse.ArgumentParser("BlastFurnace", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner)
    subparsers = p.add_subparsers(title="commands", required=True, metavar="")
    auto = subparsers.add_parser("auto", 
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=banner, help="run command in full auto mode")
    auto.add_argument("target", action="store", help="domain[/username[:password]]")
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
    auto.set_defaults(execute=execute_auto)

    generate = subparsers.add_parser("generate", 
        formatter_class=argparse.RawDescriptionHelpFormatter, description=banner,
        help="generate gMSA key")
    generate.set_defaults(execute=execute_generate)

    generate = subparsers.add_parser("offline",
        formatter_class=argparse.RawDescriptionHelpFormatter, description=banner,
        help="offline mode, all material required")
    generate.set_defaults(execute=execute_generate)

    return p.parse_args()
