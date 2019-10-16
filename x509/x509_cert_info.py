# Copyright 2019 Simon E Vera-Schockner
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

versions = {0: 'v1', 1: 'v2', 2: 'v3'}

class X509CertInfo(object):
    def __init__(self, cert_string):
        self.cert_string = cert_string
        self.cert_dict = {}

        self.loaded_cert = x509.load_pem_x509_certificate(cert_string, default_backend())

    def parse(self):
        self.cert_dict['issuer'] = self.get_issuer()
        self.cert_dict['serial_number'] = self.loaded_cert.serial_number
        self.cert_dict['version'] = self.get_version()
        self.cert_dict['signature_algorithm_oid'] = self.get_signature_algorithm_oid()
        self.cert_dict['subject'] = self.get_subject()
        self.cert_dict['public_key_algorithm'] = self.get_public_key_algorithm()
        self.cert_dict['extensions'] = self.get_extensions()
        #self.cert_dict['public_key'] = self.get_public_key()

    def to_json(self):
        return json.dumps(self.cert_dict)

    def to_pretty_json(self):
        return json.dumps(self.cert_dict, sort_keys = False, indent=4)

    def to_dict(self):
        return self.cert_dict

    def get_issuer(self):
        return self.parse_attributes(self.loaded_cert.issuer)

    def get_subject(self):
        return self.parse_attributes(self.loaded_cert.subject)

    def get_version(self):
        return versions[self.loaded_cert.version.value]

    def get_public_key_algorithm(self):
        return self.public_key_algorithm_to_string(self.loaded_cert.public_key())

    def get_extensions(self):
        return self.parse_extensions(self.loaded_cert.extensions)

    @staticmethod
    def public_key_algorithm_to_string(public_key):
        key_type = ''
        if isinstance(public_key, rsa.RSAPublicKey):
            key_type = 'RSAPublicKey'
        elif isinstance(public_key, rsa.DSAPublicKey):
            key_type = 'DSAPublicKey'
        elif isinstance(key_type, rsa.EllipticCurvePublicKey):
            key_type = 'EllipticCurvePublicKey'
        else:
            key_type = 'unknown'
        return key_type

    def get_signature_algorithm_oid(self):
        return self.loaded_cert.signature_algorithm_oid.dotted_string

    def get_loaded_cert(self):
        return self.loaded_cert

    @staticmethod
    def parse_attributes(attributes):
        attribute_list = []
        for attribute in attributes:
            extension = {}
            oid = attribute.oid.dotted_string
            name = attribute.oid._name
            value = attribute.value
            attribute_list.append({'oid': oid, 'name': name, 'value': value})

        return attribute_list

    @staticmethod
    def parse_extension(extension):
        oid = extension.oid.dotted_string
        name = extension.oid._name
        value = X509CertInfo.parse_extension_value(oid, extension.value)  # need to make get value function
        critical = extension.critical
        return {'oid': oid, 'name': name, 'value': value, 'critical': critical}

    @staticmethod
    def parse_extensions(extensions):
        extensions_list = []
        for extension in extensions:
            extensions_list.append(X509CertInfo.parse_extension(extension))

        return extensions_list

    @staticmethod
    def parse_extension_value(oid, value):
        # EKU
        return_value = None
        # Key Usage
        if oid == '2.5.29.15':
            return_value = {'digital_signature': value.digital_signature,
            'content_commitment': value.content_commitment,
            'key_encipherment': value.key_encipherment,
            'data_encipherment': value.data_encipherment,
            'key_agreement': value.key_agreement,
            'key_cert_sign': value.key_cert_sign,
            'crl_sign': value.crl_sign}

            if return_value['key_agreement']:
                return_value['encipher_only'] = value.encipher_only
                return_value['decipher_only'] = value.decipher_only

            return return_value

        elif oid == '2.5.29.14':
            return_value = value.digest

        elif oid == '2.5.29.35':
            return_value = {'key_identifier': value.key_identifier,
                            'authority_cert_issuer': value.authority_cert_issuer,
                            'authority_cert_serial_number': value.authority_cert_serial_number}

        # crl distribution
        elif oid == '2.5.29.31':
            crl_points = []
            for crl_point in value:
                for url in crl_point.full_name:
                    crl_points.append(url.value)
            return crl_points

        # AuthorityInformationAccess
        elif oid == '1.3.6.1.5.5.7.1.1':
            aia_result = []
            for aia in value:
                #OCSP
                if aia.access_method.dotted_string == '1.3.6.1.5.5.7.48.1':
                    aia_dict = {'oid': aia.access_method.dotted_string,
                                'name': aia.access_method._name,
                                'uri': aia.access_location.value}
                    aia_result.append(aia_dict)
                #caIssuers
                elif aia.access_method.dotted_string == '1.3.6.1.5.5.7.48.2':
                    aia_dict = {'oid': aia.access_method.dotted_string,
                                'name': aia.access_method._name,
                                'uri': aia.access_location.value}
                    aia_result.append(aia_dict)
                else:
                    aia_result.append(str(aia))
            return aia_result

        # BasicConstraints
        elif oid == '2.5.29.19':
            return {'BasicConstraints': value.ca}

        # EKUs
        elif oid == '2.5.29.37':
            eku_result = {}
            for eku in value:
                if eku.dotted_string == '1.3.6.1.5.5.7.3.2':
                    eku_result['TLS Web Client Authentication'] = True
                elif eku.dotted_string == '1.3.6.1.5.5.7.3.1':
                    eku_result['TLS Web Server Authentication'] = True
                else:
                    eku_result[eku.oid.dotted_string] = True
            return eku_result

        # MS Application Policies extension
        # https://support.microsoft.com/en-us/help/287547/object-ids-associated-with-microsoft-cryptography
        elif oid == '1.3.6.1.4.1.311.21.10':
            return {'OID_APPLICATION_CERT_POLICIES': str(value)}

        elif oid == '1.3.6.1.4.1.311.21.7':
            return {'OID_CERTIFICATE_TEMPLATE': str(value)}

        elif oid == '2.5.29.17':
            sans = []
            for san in value:
                sans.append(san.value)
            return sans

        else:
            # print(oid, value)
            return str(value)
