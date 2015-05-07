# modified by Sooky Peter <xsooky00@stud.fit.vutbr.cz>
# Brno University of Technology, Faculty of Information Technology
import struct
import socket
import time
import logging
import sys

from lxml import etree
from gevent.server import StreamServer

import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk import modbus
# Following imports are required for modbus template evaluation
import modbus_tk.defines as mdef
import random

from modbus_tk.modbus import ModbusInvalidRequestError, InvalidArgumentError, DuplicatedKeyError,\
                             InvalidModbusBlockError, OverlapModbusBlockError


from conpot.protocols.modbus import slave_db
import conpot.core as conpot_core

import ConfigParser

logger = logging.getLogger(__name__)


class ModbusServer(modbus.Server):

    def __init__(self, template, template_directory, args, timeout=5):

        self.config = args.config
        self.timeout = timeout
        self.delay = None
        self.mode = None
        databank = slave_db.SlaveBase(template)

        # Constructor: initializes the server settings
        modbus.Server.__init__(self, databank if databank else modbus.Databank())

        self._setup()

        # not sure how this class remember slave configuration across instance creation, i guess there are some
        # well hidden away class variables somewhere.
        self.remove_all_slaves()
        self._configure_slaves(template)

    def _setup(self):
        # read the modbus connection settings from the configuration file, in case of improper usage terminate the program
        config = ConfigParser.ConfigParser()
        config.read(self.config)
        self.mode = config.get('modbus','mode')
        try:
            if str(self.mode).lower() != 'tcp' and str(self.mode).lower() != 'serial':
                logger.error('Conpot modbus initialization failed due to incorrect settings. Check the configuration file')
                sys.exit(3)
        except (AttributeError):
            logger.error('Could not initialize modbus with current settings. Check configuration file.')
            sys.exit(3)


    def _configure_slaves(self, template):
        dom = etree.parse(template)
        self.delay = int(dom.xpath('//modbus/delay/text()')[0])
        slaves = dom.xpath('//modbus/slaves/*')
        try:
            for s in slaves:
                slave_id = int(s.attrib['id'])
                slave = self.add_slave(slave_id)
                logger.debug('Added slave with id {0}.'.format(slave_id))
                for b in s.xpath('./blocks/*'):
                    name = b.attrib['name']
                    request_type = eval('mdef.' + b.xpath('./type/text()')[0])
                    start_addr = int(b.xpath('./starting_address/text()')[0])
                    size = int(b.xpath('./size/text()')[0])
                    slave.add_block(name, request_type, start_addr, size)
                    logger.debug('Added block {0} to slave {1}. (type={2}, start={3}, size={4})'.format(
                        name, slave_id, request_type, start_addr, size
                    ))

            logger.info('Conpot modbus initialized')
        except (Exception, DuplicatedKeyError) as e:
            logger.info(e)

    def handle(self, sock, address):
        sock.settimeout(self.timeout)

        session = conpot_core.get_session('modbus', address[0], address[1])

        self.start_time = time.time()
        logger.info('New connection from %s:%s. (%s)', address[0], address[1], session.id)
        session.add_event({'type': 'NEW_CONNECTION'})

        try:
            while True:
                request = sock.recv(7)
                if not request:
                    logger.info('Client disconnected. (%s)', session.id)
                    session.add_event({'type': 'CONNECTION_LOST'})
                    break
                if request.strip().lower() == 'quit.':
                    logger.info('Client quit. (%s)', session.id)
                    session.add_event({'type': 'CONNECTION_QUIT'})
                    break
                tr_id, pr_id, length = struct.unpack(">HHH", request[:6])
                while len(request) < (length + 6):
                    new_byte = sock.recv(1)
                    request += new_byte
                query = modbus_tcp.TcpQuery()

                # logdata is a dictionary containing request, slave_id, function_code and response
                response, logdata = self._databank.handle_request(query, request, self.mode)
                logdata['request'] = request.encode('hex')

                session.add_event(logdata)

                logger.info('Modbus traffic from {0}: {1} ({2})'.format(address[0], logdata, session.id))
                if response:
                    sock.sendall(response)
                    logger.info('Modbus response sent to {0}'.format(address[0]))
                else:
                    # MB serial connection addressing UID=0
                    if (self.mode == 'serial' and logdata['slave_id'] == 0):
                        time.sleep(self.delay/1000) # millisecs
                        logger.debug('Modbus server\'s turnaround delay expired.')
                        logger.info('Connection terminated with client {0}.'.format(address[0]))
                        session.add_event({'type': 'CONNECTION_TERMINATED'})
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        break
                    # Invalid addressing
                    else:
                        logger.info('Client ignored due to invalid addressing. ({0})'.format(session.id))
                        session.add_event({'type': 'CONNECTION_TERMINATED'})
                        sock.shutdown(socket.SHUT_RDWR)
                        sock.close()
                        break

        except socket.timeout:
            logger.debug('Socket timeout, remote: %s. (%s)', address[0], session.id)
            session.add_event({'type': 'CONNECTION_LOST'})

    def start(self, host, port):
        connection = (host, port)
        server = StreamServer(connection, self.handle)
        logger.info('Modbus server started on: %s', connection)
        server.start()
