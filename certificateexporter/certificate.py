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
            certificate_suffixes):
        self.__paths = list(map(lambda s: Path(s), search_paths))
        self.__certificate_suffixes = certificate_suffixes

    @CERTIFICATEEXPORTER_LOOKUP_DURATION.time()
    def __load_ssl_certs(self):
        certs = []
        for directory in self.__paths:
            logging.debug("Looking for certs in {}".format(str(directory)))
            for file in directory.iterdir():
                logging.debug("Matching filename {} against regexes: {}..."
                              .format(file.name, self.__certificate_suffixes))
                matches = list(filter(
                    lambda f: re.search("{}$".format(f), file.name),
                    self.__certificate_suffixes))
                if len(matches) > 0 and file.is_file():
                    logging.debug("Found certificate at {}".format(str(file)))
                    cert_data = file.read_bytes()
                    cert = x509.load_pem_x509_certificate(
                        cert_data, default_backend())
                    certs.append(Cert(cert=cert, cert_path=Path(file)))
            logging.debug("Found {} SSL certificates".format(len(certs)))
        return certs

    def collect(self):
        cert_begin = GaugeMetricFamily(
            'ssl_certificate_begin_validity_timestamp',
            'Beginning of certificate validity timestamp',
            labels=['path', 'issuer', 'subjects'])
        cert_end = GaugeMetricFamily(
            'ssl_certificate_end_validity_timestamp',
            'End of certificate validity timestamp',
            labels=['path', 'issuer', 'subjects'])
        certs = self.__load_ssl_certs()
        for cert in certs:
            cert_path = str(cert.cert_path)
            cert_subjects = ";".join(cert.subjects)
            cert_issuer = cert.issuer_cn or "unknown"
            cert_begin.add_metric(
                [cert_path, cert_issuer, cert_subjects],
                cert.begin_validity)
            cert_end.add_metric(
                [cert_path, cert_issuer, cert_subjects],
                cert.end_validity)
        yield cert_begin
        yield cert_end
