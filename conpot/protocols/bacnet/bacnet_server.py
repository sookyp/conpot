# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

import logging
import re
import sys, time, socket
from lxml import etree

from ConfigParser import ConfigParser

from bacpypes.comm import Server
from gevent.server import StreamServer, DatagramServer

from bacpypes.app import LocalDeviceObject, BIPSimpleApplication
from bacpypes.pdu import GlobalBroadcast
from bacpypes.apdu import *
from bacpypes.object import *
from bacpypes.primitivedata import *

import conpot.core as conpot_core

logger = logging.getLogger(__name__)
bacnet_app = None

# TODO: fix imports

class BACnetApp(BIPSimpleApplication):

    def __init__(self, device, sock):
        self._request = None
        self._response = None
        self._response_service = None
        self.localDevice = device
        self.objectName = {device.objectName:device}
        self.objectIdentifier = {device.objectIdentifier:device}
        self.sock = sock

    def _setup(self, dom):
        property_list = []
        property_name_list = []
        bacnet_object_list = []
        # parse the bacnet template for objects
        object_list = dom.xpath('//bacnet/object_list/object/@name')
        for obj in object_list:
            property_list.insert(object_list.index(obj), dom.xpath('//bacnet/object_list/object[@name="{0}"]/properties/*'.format(obj)))
            for prop in property_list[object_list.index(obj)]:
                property_name_list.insert(property_list[object_list.index(obj)].index(prop), {prop.tag : prop.text})
                if ('object_type' in property_name_list[property_list[object_list.index(obj)].index(prop)].keys()[0]):
                    object_type = property_name_list[property_list[object_list.index(obj)].index(prop)].values()[0]
                    object_type = re.sub('-',' ',object_type)
                    object_type = object_type.lower().title()
                    object_type = re.sub(' ','',object_type)+'Object'
                    bacnet_object_list.insert(object_list.index(obj), object_type)
            try:
                # create the BACnet objects
                device_object = getattr(sys.modules[__name__], bacnet_object_list[object_list.index(obj)])()
            except (NameError):
                logger.critical('ERROR: Non-existent BACnet object type function \"{0}()\". Check template file.'.format(bacnet_object_list[object_list.index(obj)]))
                sys.exit(3)
            #
            for prop in property_list[object_list.index(obj)]:
                bacnet_property_list = property_name_list[property_list[object_list.index(obj)].index(prop)]
                bacnet_property_list_keys = bacnet_property_list.keys()[0].lower().title()
                bacnet_property_list_values = bacnet_property_list.values()[0]
                bacnet_property_list_keys = re.sub("['_','-']",'',bacnet_property_list_keys)
                bacnet_property_list_keys = bacnet_property_list_keys[0].lower()+bacnet_property_list_keys[1:]
                # assign the values to the properties and assign the properties to the objects
                if (bacnet_property_list_keys == "objectIdentifier"):
                    device_object.objectIdentifier = int(bacnet_property_list_values)
                else:
                    try:
                        setattr(device_object, bacnet_property_list_keys, bacnet_property_list_values)
                    except (PropertyError):
                        logger.critical('ERROR: Non-existent BACnet property type \"{0}\". Check template file.'.format(bacnet_property_list_keys))
                        sys.exit(3)
            # add the objects to the device
            self.add_object(device_object)

    def add_object(self, obj):
        object_name = obj.objectName
        if not object_name:
            raise RuntimeError, "object name required"
        object_identifier = obj.objectIdentifier
        if not object_identifier:
            raise RuntimeError, "object identifier required"
        if object_name in self.objectName:
            raise RuntimeError, "object already added with the same name"
        if object_identifier in self.objectIdentifier:
            raise RuntimeError, "object already added with the same identifier"

        self.objectName[object_name] = obj
        self.objectIdentifier[object_identifier] = obj
        self.localDevice.objectList.append(object_identifier)

    def indication(self, apdu, address, device):
    # logging the received PDU type and Service request
        request = None
        apdu_type = apdu_types.get(apdu.apduType)
        invoke_key = apdu.apduInvokeID
        logger.info('Bacnet PDU received from {0}:{1}. ({2})'.format(address[0], address[1], apdu_type.__name__))
        if (apdu_type.pduType == 0x0):
        # Confirmed request handling
            apdu_service = confirmed_request_types.get(apdu.apduService)
            logger.info('Bacnet indication from {0}:{1}. ({2})'.format(address[0], address[1], apdu_service.__name__))
            try:
                request = apdu_service()
                request.decode(apdu)
            except AttributeError, RuntimeError:
                logger.debug('Bacnet indication: Invalid service.')
                return
            except DecodingError:
                pass
            if (apdu_service.serviceChoice == 0x05):
                # Subscribe COV
                pass
            elif (apdu_service.serviceChoice == 0x0c):
                # Read Property
                status = False
                objPropVal = None
                objPropID = None
                objPropType = None
                # TODO: add support for PropertyArrayIndex handling
                iterator = self.iter_objects()
                try:
                    while True:
                        objectit = iterator.next()
                        objID = objectit.objectIdentifier[1]
                        objType = objectit.objectType
                        objName = objectit.objectName
                        if (int(request.objectIdentifier[1]) == int(objID)) and (request.objectIdentifier[0] == objType):
                            for key, value in objectit._properties.items():
                                if (key == request.propertyIdentifier):
                                    objPropID = value.identifier
                                    objPropVal = value.ReadProperty(objectit)
                                    objPropType = value.datatype()
                                    status = True
                                    break
                            if (status):
                                break
                            else:
                                logger.info('Bacnet ReadProperty: object has no property {0}'.format(request.propertyIdentifier))
                                self._response = ErrorPDU()
                                self._response.pduDestination = address
                                self._response.apduInvokeID = original_invoke_id
                                self._response.apduService = 0x0c
                                #self._response.errorClass
                                #self._response.errorCode
                except StopIteration:
                    pass
                if (status):
                    self._response_service = 'ComplexAckPDU'
                    self._response = ReadPropertyACK()
                    self._response.pduDestination = address
                    self._response.apduInvokeID = invoke_key
                    self._response.objectIdentifier = int(objID)
                    self._response.objectName = objName
                    self._response.propertyIdentifier = objPropID
                    
                    # TODO: make proper datatype classification
                    self._response.propertyValue = Any()
                    if isinstance(objPropType, Integer):
                        objPropVal = Integer(int(objPropVal))
                    elif isinstance(objPropType, Real):
                        objPropVal = Real(float(objPropVal))
                    elif isinstance(objPropType, CharacterString):
                        objPropVal = CharacterString(str(objPropVal))

                    self._response.propertyValue.cast_in(objPropVal)
                    
                    #self._response.debug_contents() 
                else:
                    logger.info('Bacnet ReadProperty: no object found')
                    self._response = ErrorPDU()
                    self._response.pduDestination = address
                    self._response.apduInvokeID = original_invoke_id
                    self._response.apduService = 0x0c
                    #self._response.errorClass
                    #self._response.errorCode

            elif (apdu_service.serviceChoice == 0x0e):
                # Read Property Multiple
                pass
            elif (apdu_service.serviceChoice == 0x0f):
                # Write Property
                pass
            elif (apdu_service.serviceChoice == 0x10):
                # Write Property Multiple
                pass
            elif (apdu_service.serviceChoice == 0x11):
                # Device Communication Control
                pass
            elif (apdu_service.serviceChoice == 0x14):
                # Reinitialize Device
                pass
            else:
                logger.debug('Bacnet indication: Invalid confirmed service choice ({1})'.format(apdu_service.__name__))
        # Unconfirmed request handling
        elif (apdu_type.pduType == 0x1):
            apdu_service = unconfirmed_request_types.get(apdu.apduService)
            logger.info('Bacnet indication from {0}:{1}. ({2})'.format(address[0], address[1], apdu_service.__name__))
            try:
                request = apdu_service()
                request.decode(apdu)
            except AttributeError, RuntimeError:
                logger.debug('Bacnet indication: Invalid service.')
                return
            except DecodingError:
                pass

            if (apdu_service.serviceChoice == 0x0):
                # I-Am
                # ignore
                pass

            elif (apdu_service.serviceChoice == 0x1):
                ### I-Have
                # ignore
                pass

            elif (apdu_service.serviceChoice == 0x7):
                # Who-Has
                status = False
                execute = False
                try:
                    if (request.deviceInstanceRangeLowLimit is not None) and (request.deviceInstanceRangeHighLimit is not None):
                        if (request.deviceInstanceRangeLowLimit > self.objectIdentifier.keys()[0][1]) or (self.objectIdentifier.keys()[0][1] > request.deviceInstanceRangeHighLimit):
                            logger.info('Bacnet WhoHasRequest out of range')
                        else:
                            execute = True
                    else:
                        execute = True
                except AttributeError:
                    execute = True

                if (execute):
                    iterator = self.iter_objects()
                    try:
                        while True:
                            objectit = iterator.next()
                            objID = objectit.objectIdentifier[1]
                            objType = objectit.objectType
                            objName = objectit.objectName
                            if (int(request.object.objectIdentifier[1]) == int(objID)) and (request.object.objectIdentifier[0] == objType):
                                status = True
                                break
                    except StopIteration:
                        pass
                    if (status):
                        self._response_service = 'IHaveRequest'
                        self._response = IHaveRequest()
                        self._response.pduDestination = GlobalBroadcast()

                        self._response.deviceIdentifier = self.objectIdentifier.keys()[0]
                        self._response.objectIdentifier = int(objID)
                        self._response.objectName = objName
                    else:
                        logger.info('Bacnet WhoHasRequest: no object found')
            elif (apdu_service.serviceChoice == 0x8):
                # Who-Is
                # Limits are optional (but if used, must be paired)
                execute = False
                if (request.deviceInstanceRangeLowLimit is not None) and (request.deviceInstanceRangeHighLimit is not None):
                    if (request.deviceInstanceRangeLowLimit > self.objectIdentifier.keys()[0][1]) or (self.objectIdentifier.keys()[0][1] > request.deviceInstanceRangeHighLimit):
                        logger.info('Bacnet WhoIsRequest out of range')
                    else:
                        execute = True
                else:
                    execute = True
                if (execute):
                    self._response_service = 'IAmRequest'
                    self._response = IAmRequest()
                    self._response.pduDestination = GlobalBroadcast()
                    
                    self._response.iAmDeviceIdentifier = self.objectIdentifier.keys()[0]
                    self._response.maxAPDULengthAccepted = int(device.max_apdu_length)
                    self._response.segmentationSupported = device.segmentation_supported
                    self._response.vendorID = int(device.vendor_identifier)
            else:
                # Unrecognized services
                logger.debug('Bacnet indication: Invalid unconfirmed service choice ({1})'.format(apdu_service))
                self._response_service = 'ErrorPDU'
                self._response = ErrorPDU()
                self._response.pduDestination = address
        # ignore the following
        elif (apdu_type.pduType == 0x2):
            # simple ack pdu
            pass
        elif (apdu_type.pduType == 0x3):
            # complex ack pdu
            pass
        elif (apdu_type.pduType == 0x4):
            # segment ack 
            pass
        elif (apdu_type.pduType == 0x5):
            # error pdu
            pass
        elif (apdu_type.pduType == 0x6):
            # reject pdu
            pass
        elif (apdu_type.pduType == 0x7):
            # abort pdu
            pass
        elif (0x8 <= apdu_type.pduType <= 0xf): # other stuff
            # reserved
            pass
        else:
            # non-BACnet PDU types
            logger.info('Bacnet Unrecognized service')

    def response(self, response_apdu, address):
        if isinstance(response_apdu, RejectPDU) or isinstance(response_apdu, ErrorPDU):
            apdu = APDU()
            response_apdu.encode(apdu)
            pdu = PDU()
            apdu.encode(pdu)
            self.sock.sendto(pdu.pduData, address)
        else:
            apdu_type = apdu_types.get(response_apdu.apduType)
            pdu = PDU()
            response_apdu.encode(pdu)
            if pdu.pduDestination == '*:*':
                # broadcast
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                self.sock.sendto(pdu.pduData, ('', address[1]))
            else:
                # unicast
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 0)
                self.sock.sendto(pdu.pduData, address)
            logger.info('Bacnet response sent to {0} ({1}:{2})'.format(response_apdu.pduDestination,apdu_type.__name__,self._response_service))

class BacnetServer(object):
    def __init__(self, template, template_directory, args):
        global bacnet_app
        dom = etree.parse(template)
        databus = conpot_core.get_databus()
        device_info_root = dom.xpath('//bacnet/device_info')[0]

        identifier_key = device_info_root.xpath('./device_identifier/text()')[0]
        self.device_identifier = databus.get_value(identifier_key)

        name_key = device_info_root.xpath('./device_name/text()')[0]
        self.device_name = databus.get_value(name_key)

        apdu_length_key = device_info_root.xpath('./max_apdu_length/text()')[0]
        self.max_apdu_length = databus.get_value(apdu_length_key)

        segmentation_key = device_info_root.xpath('./segmentation_support/text()')[0]
        self.segmentation_supported = databus.get_value(segmentation_key)

        vendor_key = device_info_root.xpath('./vendor_identification/text()')[0]
        self.vendor_identifier = databus.get_value(vendor_key)

        #self.local_device_address = dom.xpath('./@*[name()="host" or name()="port"]')

        self.thisDevice = LocalDeviceObject(
            objectName=self.device_name,
            objectIdentifier=int(self.device_identifier),
            maxApduLengthAccepted=int(self.max_apdu_length),
            segmentationSupported=self.segmentation_supported,
            vendorIdentifier=int(self.vendor_identifier)
        )

        # socket initialization
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.setblocking(1)
        self.sock.bind(('',47808))

        # create application instance
        bacnet_app = BACnetApp(self.thisDevice, self.sock)
        # get object_list and properties
        bacnet_app._setup(dom)

        logger.info('Conpot Bacnet initialized using the {0} template.'.format(template))

    def handle(self, data, address):
        session = conpot_core.get_session('bacnet', address[0], address[1])
        logger.info('New connection from {0}:{1}. ({2})'.format(address[0], address[1], session.id))
        session.add_event({'type': 'NEW_CONNECTION'})
        # I'm not sure if gevent DatagramServer handles issues where the received data is over the MTU -> fragmentation
        if data:
            pdu = PDU()
            pdu.pduData = data
            apdu = APDU()
            apdu.decode(pdu)
            bacnet_app.indication(apdu, address, self)
            bacnet_app.response(bacnet_app._response, address)
        logger.info('Bacnet client disconnected {0}:{1}. ({2})'.format(address[0], address[1], session.id))

    def start(self, host, port):
        connection = (host, port)
        self.server = DatagramServer(connection, self.handle)
        logger.info('Bacnet server started on: {0}'.format(connection))
        self.server.serve_forever()

    def stop(self):
        self.server.stop()
