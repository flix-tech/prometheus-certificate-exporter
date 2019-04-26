import logging
import re
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import (Certificate, NameOID,
                               SubjectAlternativeName, ExtensionNotFound)
from prometheus_client import Summary
from prometheus_client.core import GaugeMetricFamily


CERTIFICATEEXPORTER_LOOKUP_DURATION = Summary(
    "certificateexporter_lookup_duration",
    "Number of seconds it took to load all certificates"
)


class Cert:
    def __init__(self, cert, cert_path):
        self.__cert = cert
        self.__cert_path = cert_path
        self.__subjects = self.__extract_subjects(cert)

    @property
    def cert(self):
        return self.__cert

    @property
    def cert_path(self):
        return self.__cert_path

    @property
    def subjects(self):
        return self.__subjects

    @property
    def begin_validity(self):
        return self.cert.not_valid_before.timestamp()

    @property
    def end_validity(self):
        return self.cert.not_valid_after.timestamp()

    @property
    def issuer_cn(self):
        cn_list = self.__cert.issuer.get_attributes_for_oid(
            x509.OID_COMMON_NAME)
        if cn_list:
            return cn_list[0].value
        else:
            return ''

    @staticmethod
    def __extract_subjects(cert: Certificate):
        names = []
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.append(attr.value)
        try:
            san = cert.extensions.get_extension_for_class(
                SubjectAlternativeName).value
            names += map(lambda n: n.value, san)
        except ExtensionNotFound:
            pass
        return names

    def __repr__(self):
        return ('cert_path: {self.__cert_path}, '
                'subjects: {self.subjects}')


class SslCertificateExpiryHandler:
    def __init__(
            self,
            search_paths,
            certificate_suffixes,
            exclude_regex=None):
        self.__paths = list(map(lambda s: Path(s), search_paths))
        self.__certificate_suffixes = certificate_suffixes or [""]
        self.__exclude_regex = exclude_regex

    @CERTIFICATEEXPORTER_LOOKUP_DURATION.time()
    def __load_ssl_certs(self):
        certs = []
        load_error_paths = []
        for cert_path in self.__get_certpaths():
            if not self.__validate_path(cert_path):
                load_error_paths.append(str(cert_path))
                continue
            try:
                cert_data = cert_path.read_bytes()
                cert = x509.load_pem_x509_certificate(
                    cert_data, default_backend())
                certs.append(Cert(cert=cert, cert_path=cert_path))
            except Exception as e:
                logging.warning("Failed loading certificate at {}: {}: {}"
                                .format(str(cert_path), type(e).__name__, e))
                load_error_paths.append(str(cert_path))
        logging.debug("Found {} SSL certificates".format(len(certs)))
        return certs, load_error_paths

    def __validate_path(self, cert_path):
        if cert_path.exists() and cert_path.is_file():
            return True
        elif not cert_path.exists():
            logging.warning("Failed loading certificate. {} "
                            "does not exist"
                            .format(str(cert_path)))
        elif not cert_path.is_file():
            logging.warning("Failed loading certificate. {} "
                            "is not a regular file or a symlink"
                            .format(str(cert_path)))
        else:
            logging.warning("Failed loading certificate. "
                            "Unknown problem with {}"
                            .format(str(cert_path)))
        return False

    def __get_certpaths(self):
        for path in self.__paths:
            if path.is_dir():
                logging.debug("Looking for certs in {}".format(str(path)))
                for file in path.iterdir():
                    matches_suffixes = list(filter(
                        lambda f: file.name.endswith(f),
                        self.__certificate_suffixes))
                    should_be_excluded = self.__exclude_regex is not None and \
                        re.search(self.__exclude_regex, file.name)
                    if file.is_file() and \
                            len(matches_suffixes) > 0 and \
                            not should_be_excluded:
                        logging.debug("Found certificate at: "
                                      " {}".format(str(file)))
                        yield file
                    else:
                        logging.debug("File at path {} does not match suffix, "
                                      "is excluded, or is not a regular file. "
                                      "Continuing"
                                      .format(str(file)))
            else:
                yield path

    def collect(self):
        logging.debug("CertificateExporter, start metric collection...")
        cert_begin = GaugeMetricFamily(
            'ssl_certificate_begin_validity_timestamp',
            'Beginning of certificate validity timestamp',
            labels=['path', 'issuer', 'subjects'])
        cert_end = GaugeMetricFamily(
            'ssl_certificate_end_validity_timestamp',
            'End of certificate validity timestamp',
            labels=['path', 'issuer', 'subjects'])
        load_error = GaugeMetricFamily(
            'certificateexporter_load_error',
            'Certificate exporter got an error while loading certificate',
            labels=['path'])
        certs, load_error_paths = self.__load_ssl_certs()
        for cert in certs:
            cert_path = str(cert.cert_path)
            cert_subjects = ";".join([str(s) for s in cert.subjects])
            cert_issuer = cert.issuer_cn or "unknown"
            cert_begin.add_metric(
                [cert_path, cert_issuer, cert_subjects],
                cert.begin_validity)
            cert_end.add_metric(
                [cert_path, cert_issuer, cert_subjects],
                cert.end_validity)
        for path in load_error_paths:
            load_error.add_metric([path], 1)
        logging.debug("CertificateExporter, metric collection complete.")
        yield cert_begin
        yield cert_end
        yield load_error
