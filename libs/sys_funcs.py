"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 10/11/2012
    Last Modified: 08/05/2015
    
    generic functions that operate at a system level

    BSD 3-Clause License
    
    Copyright (c) 2012-2016, Andres Andreu, neuroFuzz LLC
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
import sys
import os
import fnmatch
import socket
import logging
import platform


def get_lock(process_name='', process_description=''):
    ''' Sets domain socket as locking mechanism for named process '''
    if not process_description:
        process_description = process_name
    global lock_socket   # Without this our lock gets garbage collected
    lock_socket = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
    try:
        lock_socket.bind('\0' + process_name)
        return True
    except socket.error:
        logging.info("process '%s' - error acquiring lock" % process_description)
        return False
    except Exception:
        return False


def get_python_version():
    ''' Finds the version of python in use '''
    return platform.python_version()


def which(program=""):
    ''' Finds location (path) of executable code '''
    def is_exe(fpath):
        return os.path.exists(fpath) and os.access(fpath, os.X_OK)

    def ext_candidates(fpath):
        yield fpath
        for ext in os.environ.get("PATHEXT", "").split(os.pathsep):
            yield fpath + ext

    fpath, fname = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        tarr = os.environ["PATH"].split(os.pathsep)
        tarr.append("/sbin")
        tarr.append("./")
        for path in tarr:
            exe_file = os.path.join(path, program)
            for candidate in ext_candidates(exe_file):
                if is_exe(candidate):
                    return candidate
    return None


def find_file(filename='', top="/"):
    ''' Walk the path and look for 'filename' '''
    for path, dirlist, filelist in os.walk(top):
        for name in fnmatch.filter(filelist, filename):
            return os.path.join(path, name)
    return None


def get_os_string():
    ''' Finds the linux distribution in use '''
    return platform.linux_distribution()[0]
