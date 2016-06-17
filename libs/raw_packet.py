'''

'''
import random
import socket
from struct import *


def checksum(msg):
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
    
    packet = '';
 
    source_ip = src
    dest_ip = dst

    ''' 
    # ip header fields
    ihl = 5
    version = 4
    tos = 0
    tot_len = 20 + 20   # python seems to correctly fill the total length, dont know how ??
    id = 54321  #Id of this packet
    frag_off = 0
    ttl = 255
    protocol = socket.IPPROTO_TCP
    check = 10  # python seems to correctly fill the checksum
    saddr = socket.inet_aton ( source_ip )  # spoof the source ip address
    daddr = socket.inet_aton ( dest_ip )
 
    ihl_version = (version << 4) + ihl
     
    # the ! in the pack format string means network order
    ip_header = pack('!BBHHHBBH4s4s' , ihl_version, tos, tot_len, id, frag_off, ttl, protocol, check, saddr, daddr)
    '''
    ip_header = create_ip_header(src_ip=source_ip, dst_ip=dest_ip)
    
    ''' 
    # tcp header fields
    source = 1234   # source port
    dest = 80   # destination port
    seq = 0
    ack_seq = 0
    doff = 5    #4 bit field, size of tcp header, 5 * 4 = 20 bytes
    #tcp flags
    fin = 0
    syn = 1
    rst = 0
    psh = 0
    ack = 0
    urg = 0
    window = socket.htons (5840)    #   maximum allowed window size
    check = 0
    urg_ptr = 0
     
    offset_res = (doff << 4) + 0
    tcp_flags = fin + (syn << 1) + (rst << 2) + (psh <<3) + (ack << 4) + (urg << 5)
     
    # the ! in the pack format string means network order
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, check, urg_ptr)
     
    # pseudo header fields
    source_address = socket.inet_aton(source_ip)
    dest_address = socket.inet_aton(dest_ip)
    placeholder = 0
    protocol = socket.IPPROTO_TCP
    tcp_length = len(tcp_header)
     
    psh = pack('!4s4sBBH' , source_address , dest_address , placeholder , protocol , tcp_length);
    psh = psh + tcp_header;
     
    tcp_checksum = checksum(psh)
     
    # make the tcp header again and fill the correct checksum
    tcp_header = pack('!HHLLBBHHH' , source, dest, seq, ack_seq, offset_res, tcp_flags,  window, tcp_checksum , urg_ptr)
    '''
    tcp_header = create_tcp_syn_header(src_ip=source_ip, dst_ip=dest_ip, dst_port=80)
 
    # final full packet - syn packets dont have any data
    packet = ip_header + tcp_header
    
    return packet
