"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 12/31/2015
    Last Modified: 06/17/2016
    
    functions to facilitate TCP port scanning via raw sockets

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
import socket
from raw_packet import *


def create_raw_socket(is_target_local=False):
    ''' create a raw socket with a short timeout '''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
    except socket.error , msg:
        print '%s - %s' % (str(msg[0]), msg[1])
        sys.exit()
    
    '''
        if LAN based then aggressive timeout
        is possible
    '''
    if is_target_local:
        s.settimeout(.2)
    else:
        # TODO if remote what timeout ????
        s.settimeout(5)
    # tell kernel not to put in headers since we are providing it
    s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    return s


def raw_port_scan_range(src_ip='', dst_ip='', start_port=0, end_port=65535, dst_local=False):
    
    syn_ack_received = []

    for p_in_range in range(start_port, end_port):
        #print p_in_range
        s = create_raw_socket(is_target_local=dst_local)
        
        ip_header = create_ip_header(src_ip, dst_ip)
        tcp_header = create_tcp_syn_header(src_ip, dst_ip, p_in_range)
        
        packet = ip_header + tcp_header
        
        s.sendto(packet, (dst_ip,0))
        
        try:
            data = s.recvfrom(1024) [0][0:]
            
            ip_header_len = (ord(data[0]) & 0x0f) * 4
            ip_header_ret = data[0: ip_header_len - 1]
            tcp_header_len = (ord(data[32]) & 0xf0)>>2
            tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1]
            
            if ord(tcp_header_ret[13]) == 0x12: # SYN/ACK flag set
                syn_ack_received.append(p_in_range)
        except socket.timeout:
            continue

    return syn_ack_received


def raw_port_scan_single(src_ip='', dst_ip='', port=0, dst_local=False):
    
    s = create_raw_socket(is_target_local=dst_local)
    
    ip_header = create_ip_header(src_ip, dst_ip)
    tcp_header = create_tcp_syn_header(src_ip, dst_ip, port)
    
    packet = ip_header + tcp_header
    
    s.sendto(packet, (dst_ip,0))
    
    try:
        data = s.recvfrom(1024) [0][0:]
        
        ip_header_len = (ord(data[0]) & 0x0f) * 4
        ip_header_ret = data[0: ip_header_len - 1]
        tcp_header_len = (ord(data[32]) & 0xf0)>>2
        tcp_header_ret = data[ip_header_len:ip_header_len+tcp_header_len - 1]
        
        if ord(tcp_header_ret[13]) == 0x12: # SYN/ACK flag set
            return port
    except socket.timeout:
        pass
    
    return None
