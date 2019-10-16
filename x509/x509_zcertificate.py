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

import subprocess
import json
import os

from subprocess import PIPE

paths = os.environ["PATH"].split(os.pathsep)

for path in paths:
    zcertificate_binary = os.path.join(path, 'zcertificate')
    if os.path.isfile(zcertificate_binary) and os.access(zcertificate_binary, os.X_OK):
        break

else:
    raise Exception("zcertificate binary not found in %s" % paths)

# zcertificate_binary = '/Users/sverasch/go/bin/zcertificate'

class X509Zcertificate(object):
    def __init__(self, cert_string):
        self.cert_string = cert_string #cert_string.encode('utf-8')
        self.json = None

    def parse(self):
        proc = subprocess.Popen([zcertificate_binary], stdin=PIPE, stdout=PIPE)
        out, err = proc.communicate(self.cert_string)
        self.json = out
        if err:
            raise Warning("Error parsing certificate, %s" % err)

    def to_json(self):
        return self.json

    def to_dict(self):
        return json.loads(self.json)
