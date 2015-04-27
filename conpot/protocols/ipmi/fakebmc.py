# Author: Peter Sooky <xsooky00@stud.fit.vubtr.cz>
# Brno University of Technology, Faculty of Information Technology

# using pyghmi implementation of IPMI 
import gevent
from gevent import socket
from gevent.server import DatagramServer

import struct
import os, sys

import logging

import pyghmi
import pyghmi.ipmi.private.constants as constants

from pyghmi.ipmi.private.session import Session
from pyghmi.ipmi.bmc import Bmc

import traceback
import random
import uuid
import hmac
import hashlib
from Crypto.Cipher import AES


logger = logging.getLogger()

class FakeBmc(Bmc):

    def __init__(self, authdata, port):
        self.authdata = authdata
        self.port = 6230
        self.powerstate = 'off'
        self.bootdevice = 'default'
        logger.info('IPMI BMC initialized.')

    def get_boot_device(self):
        logger.info('IPMI BMC Get_Boot_Device request.')
        return self.bootdevice

    def set_boot_device(self, bootdevice):
        logger.info('IPMI BMC Set_Boot_Device request.')
        self.bootdevice = bootdevice

    def cold_reset(self):
        logger.info('IPMI BMC Cold_Reset request.')
        self.powerstate = 'off'
        self.bootdevice = 'default'

    def get_power_state(self):
        logger.info('IPMI BMC Get_Power_State request.')
        return self.powerstate

    def power_off(self):
        logger.info('IPMI BMC Power_Off request.')
        self.powerstate = 'off'

    def power_on(self):
        logger.info('IPMI BMC Power_On request.')
        self.powerstate = 'on'

    def power_reset(self):
        logger.info('IPMI BMC Power_Reset request.')
        self.powerstate = 'off'

    def power_cycle(self):
        logger.info('IPMI BMC Power_Cycle request.')
        if self.powerstate == 'off':
            self.powerstate = 'on'
        else:
            self.powerstate = 'off'

    def power_shutdown(self):
        logger.info('IPMI BMC Power_Shutdown request.')
        self.powerstate = 'off'

