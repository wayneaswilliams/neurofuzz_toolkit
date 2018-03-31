"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 7/11/2015
    Last Modified: 03/29/2018

    modifies a proxychains.conf template and generates a version of this file
    for use by proxychains

    BSD 3-Clause License

    Copyright (c) 2015-2018, Andres Andreu, neuroFuzz LLC
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
import os
import sys
import optparse
import subprocess
import platform
import socket
from nftk_sys_funcs import is_a_file
#################################################################
class proxychains_conf_mod(object):

    def __init__(self, proxychains_conf_file_template=''):
        if proxychains_conf_file_template:
            self.proxychains_conf_file_template = proxychains_conf_file_template
        else:
            if is_a_file(fpath="./proxychains.conf.template"):
                self.proxychains_conf_file_template = "./proxychains.conf.template"
            elif is_a_file(fpath="libs/proxychains.conf.template"):
                self.proxychains_conf_file_template = "libs/proxychains.conf.template"

        self.proxychains_file = "./proxychains.conf"

        self.raw_lines = []
        # read in proxychains_config data
        self.consume_proxychains_config_file()

        self.proxy_server_list = []


    def add_proxy_servers_to_list(self, thelist=[]):
        if thelist:
            for tlist in thelist:
                t_str = "{}  {} {}".format('socks5', tlist[0], tlist[1])
                if t_str not in self.proxy_server_list:
                    self.proxy_server_list.append(t_str)


    def consume_proxychains_config_file(self):
        ''' read in proxychains config data for us to modify '''
        with open(self.proxychains_conf_file_template, "r") as f:
            self.raw_lines = f.readlines()


    def write_proxychains_conf_file(self):
        if len(self.raw_lines) > 0:
            with open(self.proxychains_file, "w") as f:
                f.write(self.dump_modified_config() + '\n')


    def dump_modified_config(self):
        #return ''.join(self.raw_lines).strip()
        return ''.join(self.raw_lines)


    def modify(self):
        the_ix = 0
        if len(self.raw_lines) > 0:
            for index,item in enumerate(self.raw_lines):
                #print "%d - %s" % (index,item)
                if item.startswith('socks'):
                    the_ix = index

            '''
                socks5  127.0.0.1 9050
            '''
            '''
            print the_ix
            print self.raw_lines[the_ix]
            '''
            if the_ix > 0:
                del self.raw_lines[-1]
                #print
                for s_kn_port in self.proxy_server_list:
                    self.raw_lines.append("{}\n".format(s_kn_port))
            else:
                for s_kn_port in self.proxy_server_list:
                    self.raw_lines.append("\n{}".format(s_kn_port))
                self.raw_lines.append("\n")
#################################################################


'''
    API
'''
def neurofuzz_modify_proxychains_conf(t_list=[]):
    ''' '''
    if len(t_list) > 0:
        proxychainsconf = proxychains_conf_mod()

        #proxychainsconf.write_proxychains_conf_file()
        proxychainsconf.consume_proxychains_config_file()
        proxychainsconf.add_proxy_servers_to_list(thelist=t_list)
        proxychainsconf.modify()
        #print proxychainsconf.dump_modified_config()
        proxychainsconf.write_proxychains_conf_file()


if __name__ == "__main__":
    neurofuzz_modify_proxychains_conf()
