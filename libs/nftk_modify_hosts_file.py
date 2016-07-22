'''
    FILENAME     : modify_hosts_file.py
    AUTHORS      : Andres Andreu <andres [at] neurofuzzsecurity dot com>
    MODIFIED BY  : Andres Andreu
    DATE         : 07/11/2015
    LAST UPDATE  : 05/18/2016
    
    modifies an /etc/hosts file and then has the ability to reset it
    back to its original state
    
    the intent here it that this be used via the 2 API's:
    
    neurofuzz_modify_hosts_file(list)
    neurofuzz_reset_hosts_file()
    
    example:
    
    neurofuzz_modify_hosts_file([('ip','host'),('ip1','host1')])
    ... 
    do your thing
    ...
    neurofuzz_reset_hosts_file()
    
    #################################################################
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
    #################################################################
    *** Take note:
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legitimate
    pen-testing and auditing purposes.
    ***
    
    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition - Dre
    #################################################################
    TODO:
    
    - currently this is for singleton use and needs to be extended for
    multiple simultaneous use
'''
import os
import sys
import hashlib
import shutil
import subprocess
import platform

#################################################################

def md5_of_file(path, block_size=256*128, out_hex=False):
    md5 = hashlib.md5()
    with open(path,'rb') as f:
        for chunk in iter(lambda: f.read(block_size), b''):
             md5.update(chunk)
    if out_hex:
        return md5.hexdigest()
    return md5.digest()


def copy_file(src='', dst=''):
    if src and dst:
        shutil.copy (src, dst)

#################################################################
class hosts_file_mod(object):

    def __init__(self):
        self.hosts_file = "/etc/hosts"
        self.hosts_file_bkup = ".etc_hosts"
        self.raw_lines = []
        self.new_hosts_list = []
        
        self.original_hosts_file = []
        self.original_hosts_file_sig = md5_of_file(path=self.hosts_file, out_hex=True)


    def add_hosts_to_list(self, thelist=[]):
        if thelist:
            for tlist in thelist:
                t_str = "%s\t%s" % (tlist[0], tlist[1])
                if t_str not in self.new_hosts_list:
                    self.new_hosts_list.append(t_str)


    def consume_hosts_file(self):
        ''' read in hosts file data for us to modify '''
        with open(self.hosts_file, "r") as f:
            self.raw_lines = f.readlines()
            ''' backup copy of the original content '''
            self.original_hosts_file = self.raw_lines[:]
            copy_file(src=self.hosts_file, dst=self.hosts_file_bkup)
            
            
    def write_hosts_file(self):
        if len(self.raw_lines) > 0:
            '''
                "w" - opens a file for writing only.
                Overwrites the file if the file exists.
                If the file does not exist, creates a new file for writing.
            '''
            with open(self.hosts_file, "w") as f:
                f.write(self.dump_modified_hosts() + '\n')
            
    
    def dump_modified_hosts(self):
        #return ''.join(self.raw_lines).strip()
        return (''.join(self.raw_lines))[:-1]
    
    
    def dump_original_hosts(self):
        #return ''.join(self.raw_lines).strip()
        return ''.join(self.original_hosts_file)


    def modify(self):
        if len(self.new_hosts_list) > 0:
            for new_host in self.new_hosts_list:
                self.raw_lines.append(new_host + '\n')
            

    def reset_hosts_file(self):
        copy_file(src=self.hosts_file_bkup, dst=self.hosts_file)

#################################################################


'''
    API
'''
def neurofuzz_modify_hosts_file(t_list=[]):
    
    hostsfilemod = hosts_file_mod()
    hostsfilemod.consume_hosts_file()
    hostsfilemod.add_hosts_to_list(t_list)
    '''
    print hostsfilemod.dump_modified_hosts()
    hostsfilemod.add_hosts_to_list([('127.0.0.1','blah.onion'),('127.0.0.1','blah2.onion')])
    '''
    hostsfilemod.modify()
    hostsfilemod.write_hosts_file()
    '''
    print hostsfilemod.dump_modified_hosts()
    print
    print hostsfilemod.dump_original_hosts()
    print hostsfilemod.original_hosts_file_sig
    import time
    time.sleep(20)
    hostsfilemod.reset_hosts_file()
    '''

    
def neurofuzz_reset_hosts_file():
    hostsfilemod = hosts_file_mod()
    hostsfilemod.reset_hosts_file()


'''
    simple test - during the sleep do:
    
        cat /etc/hosts
        
    and you should see those 2 entries added to the hosts file.
    then when the test is over do the cat again and the 2
    test entries should be gone
'''
if __name__ == "__main__":
    neurofuzz_modify_hosts_file([('127.0.0.1','blah.onion'),('127.0.0.1','blah2.onion')])
    import time
    time.sleep(20)
    neurofuzz_reset_hosts_file()
