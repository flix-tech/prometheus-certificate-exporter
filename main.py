#!/usr/bin/env python3

import argparse
import logging
import signal

import prometheus_client

from certificateexporter import certificate


def main(args):
    prometheus_client.core.REGISTRY.register(
        certificate.SslCertificateExpiryHandler(
            args.path,
            args.certificate_suffix,
            args.certificate_exclude_regex
        )
    )
    prometheus_client.start_http_server(args.port)
    signal.pause()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '--path', action='append', default=[], required=True,
        help='Path in which to look for certificates. '
             'If it\'s a directory will look for files inside it. '
             'If it\'s a file it will check it '
             'ignoring filename suffix matching and exclusion '
             '(files are not constrained by '
             ' --certificate-suffix and --certificate-exclude-regex '
             'options)'
    )
    parser.add_argument(
        '--certificate-suffix', action='append', default=[],
        help='Suffix to match against, when looking for certificates. '
             'Defaults to no suffix, so every file will be matched.'
    )
    parser.add_argument(
        '--certificate-exclude-regex', type=str, default=None,
        help='Regex to match against cert names. Matching filenames '
             'will be ignored. Optional.'
    )
    parser.add_argument(
        '--log-level', type=str, default="INFO",
        help='Set the logging level. Defaults to INFO.'
    )
    parser.add_argument(
        '--port', type=int, default="8080",
        help='Port the exporter will listen on.'
    )
    parsed_args = parser.parse_args()
    logging.getLogger()
    logging.basicConfig(
        format='%(asctime)s %(levelname)s %(message)s',
        level=parsed_args.log_level,
        datefmt='%Y-%m-%dT%H:%M:%S%z')
    logging.info(
        "Starting with given arguments: {}".format(parsed_args)
    )
    main(parsed_args)
