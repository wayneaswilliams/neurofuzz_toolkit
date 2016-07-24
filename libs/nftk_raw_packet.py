"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 12/29/2015
    Last Modified: 06/17/2016
    
    some functions to facilitate the creation of crafted raw packets
    
    the original source/ideas came from:
    http://www.arti-sec.com/article/spse-module-2-lesson-4-syn-scanner-python
    

    BSD 3-Clause License
    
    Copyright (c) 2015-2016, Andres Andreu, neuroFuzz LLC
    All rights reserved.
    
    Redistribution and use in source and binary forms, with or without modification,
    are permitted provided that the following conditions are met:
    
    1. Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    
    2. Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation and/or
    other materials provided with the distribution.
    
    3. Neither the name of the copyright holder nor the names of its contributors may
    be used to endorse or promote products derived from this software without specific
    prior written permission.
    
    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
    EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
    OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
    IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
    INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
    BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA,
    OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
    WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
    ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
    OF SUCH DAMAGE.
    
    *** Take note:
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legitimate
    pen-testing and auditing purposes.
    ***
    
    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition - Dre 
"""
import random
import socket
from struct import *


def checksum(msg):
    ''' '''
    
    s = 0
    # loop taking 2 characters at a time
    for i in range(0, len(msg), 2):
        w = (ord(msg[i]) << 8) + (ord(msg[i+1]) )
        s = s + w
     
    s = (s>>16) + (s & 0xffff);
    #s = s + (s >> 16);
    #complement and mask to 4 byte short
    s = ~s & 0xffff
     
    return s


def create_ip_header(src_ip='', dst_ip=''):
    ''' create_ip_header '''
    
    headerlen = 5
    version = 4
    tos = 0
    tot_len = 20 + 20
    id = random.randrange(18000, 65535, 1)
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10
    saddr = socket.inet_aton(src_ip)
    daddr = socket.inet_aton(dst_ip)
    hl_version = (version << 4) + headerlen
    ip_header = pack('!BBHHHBBH4s4s', hl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    
    return ip_header


def create_tcp_syn_header(src_ip='', dst_ip='', dst_port=0):
    ''' create_tcp_syn_header '''
    
    source = random.randrange(32000, 62000, 1)
    seq = 0
    ack_seq = 0
    doff = 5
    
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (8192)
    check = 0
    urg_ptr = 0
    
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh << 3) + (ack << 4) + (urg << 5)
    tcp_header = pack('!HHLLBBHHH', source, dst_port, seq, ack_seq, offset_res, tcp_flags, window, check, urg_ptr)
    
    source_address = socket.inet_aton(src_ip)
    dest_address = socket.inet_aton(dst_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
    
    psh = pack('!4s4sBBH', source_address, dest_address, placeholder, protocol, tcp_length);
    psh = psh + tcp_header;
    
    tcp_checksum = checksum(psh)
    
    tcp_header = pack('!HHLLBBHHH', source, dst_port, seq, ack_seq, offset_res, tcp_flags, window, tcp_checksum, urg_ptr)
    
    return tcp_header

def construct_raw_packet(src='', dst=''):
    ''' '''
    
    packet = '';
    if src and dst:
        source_ip = src
        dest_ip = dst
    
        ip_header = create_ip_header(src_ip=source_ip, dst_ip=dest_ip)
        tcp_header = create_tcp_syn_header(src_ip=source_ip, dst_ip=dest_ip, dst_port=80)
     
        # syn packets dont have any data so this is enuf
        packet = ip_header + tcp_header
    
    return packet
