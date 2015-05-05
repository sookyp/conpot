# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

# using pyghmi implementation of IPMI

# Copyright 2015 Lenovo
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
import gevent
from gevent import socket
from gevent.server import DatagramServer

import struct
import os, sys

import logging
import time

import pyghmi
import pyghmi.ipmi.private.constants as constants
import pyghmi.ipmi.private.serversession

import traceback
import random
import uuid
import hmac
import hashlib
from Crypto.Cipher import AES


from lxml import etree

from fakebmc import FakeBmc
from fakesession import FakeSession

logger = logging.getLogger()

class IpmiServer(object):

    def __init__(self, template, template_directory, args):
        dom = etree.parse(template)
        self.device_name = dom.xpath('//ipmi/device_info/device_name/text()')[0]
        self.host = ''
        self.port = 623
        self.sessions = dict()

        self.uuid = uuid.uuid4()
        self.kg = None

        self.authdata = {}        

        lanchannel = 1
        authtype = 0b10000000  # ipmi2 only
        authstatus = 0b00000100  # change based on authdata/kg
        chancap = 0b00000010  # ipmi2 only
        oemdata = (0, 0, 0, 0)
        self.authcap = struct.pack('BBBBBBBBB', 0, lanchannel, authtype, authstatus, chancap, *oemdata)

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(1)
        self.sock.bind(('', 623))
        self.bmc = self._setup(dom)
        logger.info('Conpot IPMI initialized using {0} template'.format(template))

    def _setup(self, dom):
        # XML parsing
        self.privdata = {}
        authdata_name = dom.xpath('//ipmi/user_list/user/user_name/text()')
        authdata_passwd = dom.xpath('//ipmi/user_list/user/password/text()')
        self.authdata = dict(zip(authdata_name, authdata_passwd))
        authdata_priv = dom.xpath('//ipmi/user_list/user/privilege/text()')
        if False in map(lambda k: 0<int(k)<=4, authdata_priv):
            raise ValueError, "Privilege level must be between 1 and 4"
        authdata_priv = [int(k) for k in authdata_priv]
        self.privdata = dict(zip(authdata_name, authdata_priv))
        activeusers = dom.xpath('//ipmi/user_list/user/active/text()')
        self.activeusers = sum([1 if x=='true' else 0 for x in activeusers])
        fixedusers = dom.xpath('//ipmi/user_list/user/fixed/text()')
        self.fixedusers = sum([1 if x=='true' else 0 for x in fixedusers])
        
        self.channelaccessdata = dict(zip(authdata_name, activeusers))

        return FakeBmc(self.authdata, self.port)

    def _checksum(self, *data):
        csum = sum(data)
        csum ^= 0xff
        csum += 1
        csum &= 0xff
        return csum

    def handle(self, data, address):
        
        if not address[0] in self.sessions.keys():
            # 1st run
            logger.info('New IPMI traffic from {0}'.format(address))
            self.session = FakeSession(address[0], "", "", address[1])
            self.session.server = self

            self.session.socket = self.sock
            self.sessions[address[0]] = self.session
            self.initiate_session(data, address, self.session)
        else:
            # not 1st run; session already exists
            logger.debug('Incoming IPMI traffic from {0}'.format(address))
            if self.session.stage == 0:
                self.close_server_session()
            else:
                self._got_request(data, address, self.session)

    def initiate_session(self, data, address, session):
        # classify received data
        if len(data) < 22: 
            self.ipmiserver.close_server_session()
            return
        if not (data[0]=='\x06' and data[2:4]=='\xff\x07'):
            # check rmcp version, sequencenumber and class;
            self.close_server_session() # cleanup
            return
        if data[4] == '\x06':  # ipmi v2
            session.ipmiversion = 2.0
            session.authtype = 6
            payload_type = data[5]
            if payload_type not in ('\x00', '\x10'):
                self.close_server_session() # cleanup
                return
            if payload_type == '\x10':  # new session to handle conversation
                serversession.ServerSession(self.authdata, self.kg, session.sockaddr,
                              self.sock, data[16:], self.uuid,
                              bmc=self)
                return
            data = data[13:]  # ditch 13 bytes so the payload works out
        myaddr, netfnlun = struct.unpack('2B', data[14:16])
        netfn = (netfnlun & 0b11111100) >> 2
        mylun = netfnlun & 0b11
        if netfn == 6:  # application request
            if data[19] == '\x38':  # cmd = get channel auth capabilities
                verchannel, level = struct.unpack('2B', data[20:22])
                version = verchannel & 0b10000000
                if version != 0b10000000:
                    self.close_server_session() # cleanup
                    return
                channel = verchannel & 0b1111
                if channel != 0xe:
                    self.close_server_session() # cleanup
                    return
                (clientaddr, clientlun) = struct.unpack('BB', data[17:19])
                level &= 0b1111
                self.send_auth_cap(myaddr, mylun, clientaddr, clientlun, session.sockaddr)

    def send_auth_cap(self, myaddr, mylun, clientaddr, clientlun, sockaddr):
        header = '\x06\x00\xff\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10'
        # header information: ...

        headerdata = (clientaddr, clientlun | (7 << 2))
        headersum = self._checksum(*headerdata)
        header += struct.pack('BBBBBB',
                              *(headerdata + (headersum, myaddr, mylun, 0x38)))
        header += self.authcap
        bodydata = struct.unpack('B' * len(header[17:]), header[17:])
        header += chr(self._checksum(*bodydata))
        self.session.stage += 1
        logger.debug('Connection established with {0}'.format(sockaddr))
        self.session.send_data(header, sockaddr)

    def close_server_session(self):
        logger.info('IPMI Session closed {0}'.format(self.session.sessionid))
        # cleanup procedure
        del self.sessions[self.session.sockaddr[0]]
        self.session = None

        pass

    def _got_request(self, data, address, session):
        if data[4] in ('\x00', '\x02'):  # ipmi 1.5 payload
            session.ipmiversion = 1.5
            remsequencenumber = struct.unpack('<I', data[5:9])[0]
            if (hasattr(session, 'remsequencenumber') and
                    remsequencenumber < session.remsequencenumber):
                self.close_server_session()
                return
            session.remsequencenumber = remsequencenumber
            if ord(data[4]) != session.authtype:
                self.close_server_session()
                return
            remsessid = struct.unpack("<I", data[9:13])[0]
            if remsessid != session.sessionid:
                self.close_server_session()
                return
            rsp = list(struct.unpack("!%dB" % len(data), data))
            authcode = False
            if data[4] == '\x02':  # authcode in ipmi 1.5 packet
                authcode = data[13:29]
                del rsp[13:29]
            payload = list(rsp[14:14 + rsp[13]])
            if authcode:
                expectedauthcode = session._ipmi15authcode(payload,
                                                        checkremotecode=True)
                expectedauthcode = struct.pack("%dB" % len(expectedauthcode), *expectedauthcode)
                if expectedauthcode != authcode:
                    self.close_server_session()
                    return
            session._ipmi15(payload)
        elif data[4] == '\x06': # ipmi 2.0 payload
            session.ipmiversion = 2.0
            session.authtype = 6
            session._ipmi20(data)
        else:
            self.close_server_session()
            return  # unrecognized data

    def _got_rmcp_openrequest(self, data):
        request = struct.pack('B' * len(data), *data)
        clienttag = ord(request[0])
        self.clientsessionid = list(struct.unpack('4B', request[4:8]))
        self.managedsessionid = list(struct.unpack('4B', os.urandom(4)))
        self.session.privlevel = 4
        response = ([clienttag, 0, self.session.privlevel, 0] +
                    self.clientsessionid + self.managedsessionid +
                    [
                        0, 0, 0, 8, 1, 0, 0, 0,  # auth
                        1, 0, 0, 8, 1, 0, 0, 0,  # integrity
                        2, 0, 0, 8, 1, 0, 0, 0,  # privacy
                    ])
        logger.debug('IPMI open session request')
        self.session.send_payload(response,
                          constants.payload_types['rmcpplusopenresponse'],
                          retry=False)

    def _got_rakp1(self, data):
        clienttag = data[0]
        self.Rm = data[8:24]
        self.rolem = data[24]
        self.maxpriv = self.rolem & 0b111
        namepresent = data[27]
        if namepresent == 0:
            self.close_server_session()
            return
        usernamebytes = data[28:]
        self.username = struct.pack('%dB' % len(usernamebytes), *usernamebytes)
        if self.username not in self.authdata:
            self.close_server_session()
            return
        uuidbytes = self.uuid.bytes
        uuidbytes = list(struct.unpack('%dB' % len(uuidbytes), uuidbytes))
        self.uuiddata = uuidbytes
        self.Rc = list(struct.unpack('16B', os.urandom(16)))
        hmacdata = (self.clientsessionid + self.managedsessionid +
                    self.Rm + self.Rc + uuidbytes +
                    [self.rolem, len(self.username)])
        hmacdata = struct.pack('%dB' % len(hmacdata), *hmacdata)
        hmacdata += self.username
        self.kuid = self.authdata[self.username]
        if self.kg is None:
            self.kg = self.kuid
        authcode = hmac.new(self.kuid, hmacdata, hashlib.sha1).digest()
        authcode = list(struct.unpack('%dB' % len(authcode), authcode))
        newmessage = ([clienttag, 0, 0, 0] + self.clientsessionid +
                      self.Rc + uuidbytes + authcode)
        logger.debug('IPMI rakp1 request')
        self.session.send_payload(newmessage, constants.payload_types['rakp2'],
                          retry=False)

    def _got_rakp3(self, data):
        RmRc = struct.pack('B' * len(self.Rm + self.Rc), *(self.Rm + self.Rc))
        self.sik = hmac.new(self.kg,
                            RmRc +
                            struct.pack("2B", self.rolem,
                                        len(self.username)) +
                            self.username, hashlib.sha1).digest()
        self.session.k1 = hmac.new(self.sik, '\x01' * 20, hashlib.sha1).digest()
        self.session.k2 = hmac.new(self.sik, '\x02' * 20, hashlib.sha1).digest()
        self.session.aeskey = self.session.k2[0:16]

        hmacdata = struct.pack('B' * len(self.Rc), *self.Rc) +\
            struct.pack("4B", *self.clientsessionid) +\
            struct.pack("2B", self.rolem,
                        len(self.username)) +\
            self.username
        expectedauthcode = hmac.new(self.kuid, hmacdata, hashlib.sha1).digest()
        authcode = struct.pack("%dB" % len(data[8:]), *data[8:])
        if expectedauthcode != authcode:
            self.close_server_session()
            return
        clienttag = data[0]
        if data[1] != 0:
            self.close_server_session()
            return
        self.session.localsid = struct.unpack('<I',
                                      struct.pack(
                                          '4B', *self.managedsessionid))[0]

        logger.debug('IPMI rakp3 request')
        self.session.ipmicallback = self.handle_client_request
        self._send_rakp4(clienttag, 0)

    def _send_rakp4(self, tagvalue, statuscode):
        payload = [tagvalue, statuscode, 0, 0] + self.clientsessionid
        hmacdata = self.Rm + self.managedsessionid + self.uuiddata
        hmacdata = struct.pack('%dB' % len(hmacdata), *hmacdata)
        authdata = hmac.new(self.sik, hmacdata, hashlib.sha1).digest()[:12]
        payload += struct.unpack('%dB' % len(authdata), authdata)
        logger.debug('IPMI rakp4 sent')
        self.session.send_payload(payload, constants.payload_types['rakp4'],
                          retry=False)
        self.session.confalgo = 'aes'
        self.session.integrityalgo = 'sha1'
        self.session.sessionid = struct.unpack(
            '<I', struct.pack('4B', *self.clientsessionid))[0]

    def handle_client_request(self, request):
        if request['netfn'] == 6 and request['command'] == 0x3b:
            # set session privilage level
            pendingpriv = request['data'][0]
            returncode = 0
            if pendingpriv > 1:
                if pendingpriv > self.maxpriv:
                    returncode = 0x81
                else:
                    self.clientpriv = request['data'][0]
            self.session._send_ipmi_net_payload(code=returncode,
                                        data=[self.clientpriv])
            logger.debug('IPMI response sent (Set Session Privilege) to {0}'.format(self.session.sockaddr))
        elif request['netfn'] == 6 and request['command'] == 0x3c:
            # close session
            self.session.send_ipmi_response()
            logger.debug('IPMI response sent (Close Session) to {0}'.format(self.session.sockaddr))
            self.close_server_session()
        elif request['netfn'] == 6 and request['command'] == 0x44:
            # get user access
            reschan = request['data'][0]
            channel = reschan & 0b00001111
            resuid = request['data'][1]
            usid = resuid & 0b00011111
            if self.clientpriv > self.maxpriv:
                # make better comparsion
                returncode = 0xd4
            else:
                returncode = 0
            self.usercount = len(self.authdata.keys())
            self.channelaccess = 0b0000000 | self.privdata[self.authdata.keys()[usid-1]]
            if self.channelaccessdata[self.authdata.keys()[usid-1]]=='true':
                self.channelaccess |= 0b00110000
            # channelaccess: 7=res;6=callin;5=link;4=messaging;3-0=privilege
            data = []
            data.append(self.usercount)
            data.append(self.activeusers)
            data.append(self.fixedusers)
            data.append(self.channelaccess)
            self.session._send_ipmi_net_payload(code=returncode,
                                        data=data)
            logger.debug('IPMI response sent (Get User Access) to {0}'.format(self.session.sockaddr))
        elif request['netfn'] == 6 and request['command'] == 0x46:
            # get user name
            userid = request['data'][0]
            returncode = 0
            username = self.authdata.keys()[userid-1]
            data = map(ord, list(username))
            while len(data) < 16:
                #filler
                data.append(0)
            self.session._send_ipmi_net_payload(code=returncode,
                                        data=data)
            logger.debug('IPMI response sent (Get User Name) to {0}'.format(self.session.sockaddr))
        else:
            # netfn == 6 || netfn == 0; application || chassis
            self.bmc.handle_raw_request(request, self.session)

    def start(self, host, port):
        connection = (host, port)
        self.server = DatagramServer(connection, self.handle)
        logger.info('IPMI server started on: {0}'.format(connection))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
