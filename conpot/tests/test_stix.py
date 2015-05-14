# Copyright (C) 2013  Johnny Vestergaard <jkv@unixcluster.dk>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import os
import uuid
from datetime import datetime
from StringIO import StringIO

import unittest
from ConfigParser import ConfigParser
from lxml import etree

from conpot.core.loggers.taxii_log import TaxiiLogger
from conpot.core.loggers.stix_transform import StixTransformer
from conpot.tests.helpers.mitre_stix_validator import STIXValidator


class TestLoggers(unittest.TestCase):

    def test_stix_transform(self):
        """
        Objective: Test if our STIX xml can be validated.
        """
        config = ConfigParser()
        config_file = os.path.join(os.path.dirname(__file__), '../conpot.cfg')
        config.read(config_file)
        config.set('stix', 'enabled', True)
        config.set('stix', 'contact_name', 'conpot')
        config.set('stix', 'contact_domain', 'http://conpot.org/stix-1')

        test_event = {'remote': ('127.0.0.1', 54872), 'data_type': 's7comm',
                      'public_ip': '111.222.111.222',
                      'timestamp': datetime.now(),
                      'session_id': str(uuid.uuid4()),
                      'data': {0: {'request': 'who are you', 'response': 'mr. blue'},
                               1: {'request': 'give me apples', 'response': 'no way'}}}
        dom = etree.parse('conpot/templates/default/template.xml')
        stixTransformer = StixTransformer(config, dom)
        stix_package_xml = stixTransformer.transform(test_event)
        xmlValidator = STIXValidator(None, True, False)
        result_dict = xmlValidator.validate(StringIO(stix_package_xml.encode('utf-8')))
        errors = ''
        if 'errors' in result_dict:
            errors = ', '.join(result_dict['errors'])
        self.assertTrue(result_dict['result'], 'Error while validations STIX xml: {0}'. format(errors))

if __name__=="__main__":
    unittest.main()
