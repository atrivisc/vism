import argparse
import json
import logging
from typing import Any, Optional

from vism_ca import VismCA

logger = logging.getLogger("cli")

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
    vism_ca = VismCA(pre_args)

    ca_parser = component_subparsers.add_parser('ca', help='CA')
    ca_subparser = ca_parser.add_subparsers(dest='ca_command', required=True, help='ca command')

    ### Get commands ###
    get_crl_parser = ca_subparser.add_parser('get_crl', help='Get a certificate crl')
    get_crl_parser.add_argument('cert_name', help='Name of the certificate')
    get_crt_parser = ca_subparser.add_parser('get_crt', help='Get a certificate pem')
    get_crt_parser.add_argument('cert_name', help='Name of the certificate')

    get_chain_parser = ca_subparser.add_parser('get_chain', help='Get a certificate chain')
    get_chain_parser.add_argument('cert_name', help='Name of the certificate')
    get_chain_parser.add_argument('--include-root', action='store_true', help='Include the root certificate in the chain', default=False)

    ### Status command ###
    status_parser = ca_subparser.add_parser('status', help='Show the status of the CA')

    ### Create command ###
    create_parser = ca_subparser.add_parser('create', help='Create a new CA')
    create_parser.add_argument('ca_cert_name',
                               help='Name of the CA or predefined option (all: create all certificates, external: create only external certificates)',
                               choices=['all', 'external', 'internal'] + [cert.name for cert in vism_ca.config.x509_certificates])

    args = parser.parse_args()

    if args.component == 'ca':

        if args.ca_command == 'status':
            return json.dumps(vism_ca.ca_status())

        if args.ca_command == 'get_crl':
            return vism_ca.get_crl(args.cert_name)

        if args.ca_command == 'get_crt':
            return vism_ca.get_crt(args.cert_name)

        if args.ca_command == 'get_chain':
            return vism_ca.get_chain(args.cert_name, args.include_root, init=True)

        if args.ca_command == 'create':
            if args.ca_cert_name == 'all':
                certificate_names = [cert.name for cert in vism_ca.config.x509_certificates]
                return vism_ca.create_certificates(certificate_names)

            if args.ca_cert_name == 'external':
                certificate_names = [cert.name for cert in vism_ca.config.x509_certificates if cert.externally_managed]
                return vism_ca.create_certificates(certificate_names)

            if args.ca_cert_name == 'internal':
                certificate_names = [cert.name for cert in vism_ca.config.x509_certificates if not cert.externally_managed]
                return vism_ca.create_certificates(certificate_names)

            return vism_ca.create_certificate(args.ca_cert_name)

    return None


if __name__ == '__main__':
    print(main())
