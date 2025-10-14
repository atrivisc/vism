import argparse

from vism_ca.main import VismCA

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', help='Path to config file.', default="./config.yaml")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose logging', default=False)
    args = parser.parse_args()

    vism = VismCA(args)
    cert_conf = vism.config.x509_certificates[0]
    vism.create_certificate(cert_conf)
