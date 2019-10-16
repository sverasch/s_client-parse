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

SESSION_FIELDS = ['Protocol',
                  'Cipher',
                  'Session-ID', 'Session-ID-ctx',  # order matters here
                  'Resumption PSK',
                  'PSK identity', 'PSK identity hint', # order matters here
                  'SRP username'
                  'TLS session ticket lifetime hint',  # TLS session ticket: Is a special case here
                  'Start Time', 'Timeout', 'Verify return code',
                  'Extended master secret',
                  'Max Early Data']

SESSION_TICKET = 'TLS session ticket'

OTHER_FIELDS = ['Peer signing digest', 'Server Temp Key']


class OpenSSLSClientParser(object):
    def __init__(self, input="", cert_parser=None):
        self.conn_info = None
        self.cert_parser = cert_parser

        if isinstance(input, list):
            self.input = input
        elif isinstance(input, str):
            self.input = input.split('\n')
        else:
            raise TypeError("Unsupported Type %s" % type(input))

    def to_json(self):
        return json.dumps(self.conn_info)

    @staticmethod
    def _extract_after_colon(value):
        try:
            split_value = value.split(': ')[1]
        except IndexError:
            split_value = ''
        return split_value

    def parse_connection_info(self):
        conn_info = {'Certificate chain': {}}
        in_cert_chain = False
        in_certificate = False
        in_ssl_session = False
        in_ssl_session_ticket = False

        certificate = {}
        chain_number = 0
        certificate_string = ""
        lineno = 0

        session_ticket = []

        for line in self.input: #
            lineno += 1

            line = line.rstrip('\n')

            if in_cert_chain:
                if line == '---':
                    in_cert_chain = False
                    continue

                elif line == '-----BEGIN CERTIFICATE-----':
                    in_certificate = True
                elif line == '-----END CERTIFICATE-----':
                    in_certificate = False
                    certificate_string += line + '\n'
                    certificate['raw'] = certificate_string.encode('utf-8')
                    conn_info['Certificate chain'][chain_number] = {}
                    conn_info['Certificate chain'][chain_number]['raw'] = certificate_string

                    if self.cert_parser:
                        cert_obj = self.cert_parser(certificate_string.encode('utf-8'))
                        cert_obj.parse()
                        cert_dict = cert_obj.to_dict()
                        conn_info['Certificate chain'][chain_number]['details'] = cert_dict
                    certificate = {}
                    certificate_string = ""
                    continue

                if in_certificate:
                    certificate_string += line + '\n'
                else:
                    subject_or_issuer = line.split(':')
                    if 's' in subject_or_issuer[0]:
                        chain_number = subject_or_issuer[0].split(' ')[1]
                        certificate['subject'] = subject_or_issuer[1]
                        certificate['chain_number'] = chain_number
                    elif 'i' in subject_or_issuer[0]:
                        certificate['issuer'] = subject_or_issuer[1]

            elif in_ssl_session:
                if line == '---':
                    in_ssl_session = False
                    conn_info['TLS session ticket'] = session_ticket
                    continue

                elif 'TLS session ticket' in line:
                    in_ssl_session_ticket = True

                elif in_ssl_session_ticket:
                    if line == '':
                        in_ssl_session_ticket = False
                    else:
                        session_ticket.append(line)
                        continue

                for keyword in SESSION_FIELDS:
                    if keyword in line:
                        conn_info[keyword] = self._extract_after_colon(line)

            else:
                for keyword in OTHER_FIELDS:
                    if keyword in line:
                        conn_info[keyword] = self._extract_after_colon(line)

            if line == '---':
                "nothing yet"
            elif line == 'Certificate chain':
                in_cert_chain = True
                # we're going to want to re
            elif line == 'SSL-Session:':
                in_ssl_session = True

        self.conn_info = conn_info



