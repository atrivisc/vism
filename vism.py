import argparse
import json
import logging

from vism_ca import VismCA

logger = logging.getLogger("cli")

def main() -> None:
    ### Base arguments ###
    pre_parser = argparse.ArgumentParser(add_help=False)
    pre_parser.add_argument('--config', help='Path to config file.', default="./config.yaml")
    pre_parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging', default=False)

    pre_args, remaining = pre_parser.parse_known_args()
    parser = argparse.ArgumentParser(parents=[pre_parser])
    component_subparsers = parser.add_subparsers(dest='component', required=True, help='component')

    ### CA ###
    vism_ca = VismCA(pre_args)

    ca_parser = component_subparsers.add_parser('ca', help='CA')
    ca_subparser = ca_parser.add_subparsers(dest='ca_command', required=True, help='ca command')

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
            return print(json.dumps(vism_ca.ca_status()))

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
    main()
