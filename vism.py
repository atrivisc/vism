import argparse
import logging
from typing import Any, Optional

import uvicorn


logger = logging.getLogger("cli")

def parse_kv_args(args: list[str]) -> dict[str, str]:
    kv_args = {}
    for arg in args:
        key, value = arg.split("=")
        kv_args[key] = value
    return kv_args

def main() -> Optional[Any]:
    ### Base arguments ###
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config', help='Path to config file.', default="./config.yaml")

    log_group = pre_parser.add_mutually_exclusive_group()
    log_group.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging', default=False)
    log_group.add_argument('-q', '--quiet', action='store_true', help='Enable quiet logging (only errors will be logged to console)', default=False)

    pre_args, remaining = pre_parser.parse_known_args()
    parser = argparse.ArgumentParser(parents=[pre_parser])
    component_subparsers = parser.add_subparsers(dest='component', required=True, help='component')

    ### CA ###
    ca_parser = component_subparsers.add_parser('ca', help='CA')
    ca_subparser = ca_parser.add_subparsers(dest='ca_command', required=True, help='ca command')
    status_parser = ca_subparser.add_parser('start', help='Run the CA api')

    ### Acme ###
    acme_parser = component_subparsers.add_parser('acme', help='ACME')
    acme_subparser = acme_parser.add_subparsers(dest='acme_command', required=True, help='acme command')
    status_parser = acme_subparser.add_parser('start', help='Run the ACME api')

    args = parser.parse_args()

    if args.component == 'ca':
        if args.ca_command == 'start':
            uvicorn.run("vism_ca.api:app", host="0.0.0.0", port=8000, reload=True)

    if args.component == 'acme':
        if args.acme_command == 'start':
            uvicorn.run("vism_acme:app", host="0.0.0.0", port=8080, reload=True)


    return None


if __name__ == '__main__':
    print(main())
