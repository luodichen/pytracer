# -*- coding: utf-8 -*-

'''
Created on Nov 9, 2016

@author: luodichen
'''

import time
import struct
import socket
import threading

from Queue import Queue
from Queue import Empty as QueueEmpty


class PyTracer(object):
    def __init__(self, host):
        self.host = host
    
        
class ICMPReceiver(object):
    class TimedoutException(Exception):
        def __init__(self):
            pass
        
    
    def __init__(self, src_host, dst_host):
        self.src_host = src_host
        self.dst_host = dst_host
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        self.sock.bind((src_host[0], 0))
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        self.sock.settimeout(0.1)
        
        self.queue = Queue()
        self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.worker_thread = threading.Thread(target=self.worker)
        self.worker_thread.start()
        
        self.exit = False
        
        
    def __enter__(self):
        return self
    
    
    def __exit__(self, exc_type, exc_value, traceback):
        self.release()
        
    
    def release(self):
        self.exit = True
        self.worker_thread.join()
    
        
    def worker(self):
        while not self.exit:
            data, address = None, None
            try:
                data, address = self.sock.recvfrom(65565)
            except socket.timeout:
                continue
            
            ip_package = IPPackage(data)
            if ip_package.protocol != socket.IPPROTO_ICMP:
                continue
    
    
    def receive(self, ttl, timeout):
        abs_timeout = time.time() + timeout
        ret = None
        
        while True:
            rel_timeout = time.time() - abs_timeout
            if rel_timeout < 0.001:
                raise self.TimedoutException()
            
            result = None
            try:
                result = self.queue.get(timeout=rel_timeout)
            except QueueEmpty:
                raise self.TimedoutException()
    
            if result[1] == ttl:
                ret = result[0]
                break
        
        return ret
    
            
class BasePackage(object):
    def __init__(self, data=None):
        if data is not None:
            field_data = struct.unpack(self._format_, data)
            
        for i in xrange(len(self._fields_)):
            if data is not None:
                self.__setattr__(self._fields_[i], field_data[i])
            else:
                self.__setattr__(self._fields_[i], None)
    
    
    def pack(self):
        data_tuple = (self.__getattribute__(f) for f in self._fields_)
        return struct.pack(self._format_, *data_tuple)
    

class IPPackage(BasePackage):
    _fields_ = [
        'version_ihl',
        'dscp_ecn',
        'total_length',
        'identification',
        'flags_fragment_offset',
        'time_to_live',
        'protocol',
        'header_checksum',
        'source_address',
        'destination_address',
        'options_load'
    ]
    
    _format_ = '!BBHHHBBHIIP'
    
    def __init__(self, data=None):
        ret = BasePackage.__init__(self, data)
        if data is not None:
            self.version = (self.version_ihl & 0xf0) >> 4
            self.header_length = (self.version_ihl & 0x0f) * 4
            self.dscp = (self.dscp_ecn & 0xfc) >> 2
            self.ecn = self.dscp_ecn & 0x03
 
            self.load = data[self.header_length:self.total_length]
        return ret
