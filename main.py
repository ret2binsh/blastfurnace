import logging
from blastfurnace.commands.parser import parse_commandline
logger = logging.getLogger(__name__)

def main():
    args = parse_commandline()
    if args.debug:
        lvl = logging.DEBUG
    else:
        lvl = logging.INFO
    logging.basicConfig(format="%(message)s", level=lvl)
    logging.debug("[!] Debug Mode Enabled")
    args.execute(args)

if __name__ == "__main__":
    main()
