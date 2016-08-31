'''
    Author:     Andres Andreu
    Contact:    <andres [at] neurofuzzsecurity dot com>
    Company:    neuroFuzz, LLC
    Date:       6/23/2012
    Modified:   8/19/2016
    
    This software runs on certain flavors of Linux and Mac OSX (written on 10.7.x with python 2.6/2.7). 
    Its intent is to temporarily change/spoof the MAC Address on the machine running it. Note that you 
    will need to be on the machine locally, not a remote shell as you will kill your own session.
    
    The code I did see out there that operates on this same functionality just lacked so much and made so many static
    and bad assumptions that I decided to just write this myself. So in the spirit of open source I am sharing this
    with the world.

    If you are running this as a standalone prog,
    
    Usage:
    
        sudo python main.py
        
        or
        
        sudo python main.py --static=60:f8:1d:b3:a1:98
        
    If there is no static MAC Address value presented with the "--static" argument
    then this prog defaults to setting a randomly generated MAC Address value.
    
    
    If WRITEDAT is set to True it stores a record of your MAC Address activity with
    this tool in a file called: ".originalMac", the data in there is structured as such:
    
        interface tab MAC_Address tab #pid#date/time_stamp
    
    where the pid is that of the prog run when that change
    was made. An example:
    
        eth0    07:c8:6f:23:32:f0    #764#2012-06-25T23:49:15.405275
        
    #################################################################
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
    #################################################################
    *** Take note:
    If you use this for criminal purposes and get caught you are on
    your own and I am not liable. I wrote this for legitimate
    pen-testing and auditing purposes.
    ***
    
    Be kewl and give credit where it is due if you use this. Also,
    send me feedback as I don't have the bandwidth to test for every
    condition or flavor of Linux under the Sun. - Dre
    #################################################################
'''
import getopt
import json
import time
import logging
import logging.config
from random import randint
from macCloaker import *

DEBUG = False

###############################################
APP_META = {'app_name':get_color_out(the_str='[neuroFuzz macCloaker] - ', the_color='yellow', do_bold=False)}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'standard': {
            'format': '%(levelname)s:%(name)s: %(message)s '
                    '(%(asctime)s; %(filename)s:%(lineno)d)',
            'datefmt': "%Y-%m-%d %H:%M:%S",
        }
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.StreamHandler',
        },
        'rotate_file': {
            'level': 'DEBUG',
            'formatter': 'standard',
            'class': 'logging.handlers.RotatingFileHandler',
            'filename': 'rotated.log',
            'encoding': 'utf8',
            'maxBytes': 100000,
            'backupCount': 1,
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'rotate_file'],
            'level': 'DEBUG',
        },
    }
}
logging.config.dictConfig(LOGGING)

log = logging.getLogger(__name__)

out_hdlr = logging.StreamHandler(sys.stdout)
#out_hdlr.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
out_hdlr.setFormatter(logging.Formatter('%(app_name)s %(message)s'))
out_hdlr.setLevel(logging.INFO)

log.addHandler(out_hdlr)
log.setLevel(logging.INFO)
log.propagate = False

log = logging.LoggerAdapter(log, APP_META)
###############################################

if __name__ == "__main__":
    
    staticval = False
    rotate_mac = False
    options, remainder = getopt.getopt(sys.argv[1:], '', ['static=','rotate'])
    
    for opt, arg in options:
        if opt == '--static':
            staticval = arg
        if opt == '--rotate':
            rotate_mac = True
            
    if staticval and rotate_mac:
        print "\nCannot process a static MAC address value and set rotation on\n\n"
        sys.exit()
            
    if staticval:
        if not validate_mac_address_format(the_mac=staticval):
            print "\n'%s' - Not a valid MAC Address\n\n" % staticval
            sys.exit()
    
    '''
        go in here for randomly chosen MAC addresses
        that will rotate at certain intervals
    '''
    if rotate_mac:
        cnt = 0
        while True:
            try:
                if cnt == 0:
                    json_out = ''
                    json_out = cloak_mac(api_logger=log, verbose=True)
                    
                    print("Now go do whatever it is you need to do with a spoofed MAC Address, wink wink ...")
                    print("Press [CTRL-C] when you want to set the Mac back to normal\n\n")
                    
                else:
                    json_out = cloak_mac(interface_name=json_out['interface_name'], api_logger=log, verbose=True)
                    
                if DEBUG:
                    print json_out

                json_out = json.loads(json_out)            
    
                sys.stdout.write("MAC Address on '%s': %s   \n" % (json_out['interface_name'],
                                                                   get_color_out(the_str=json_out['fake_mac_address'],
                                                                                 the_color='red',
                                                                                 do_bold=False).strip()
                                                                   )
                                 )
                sys.stdout.flush()
                time.sleep(randint(3900,10800))
                cnt += 1
            except KeyboardInterrupt:
                print
                break
    else:
        '''
            go in here for static set MAC addresses or
            randomly chosen MAC address that will not
            rotate
        '''
        try:
            json_out = ''
            if staticval:
                json_out = cloak_mac(staticval=staticval, api_logger=log, verbose=True)
            else:
                json_out = cloak_mac(api_logger=log, verbose=True)
                
            print("Now go do whatever it is you need to do with a spoofed MAC Address, wink wink ...")
            print("Press [CTRL-C] when you want to set the Mac back to normal\n\n")

            if DEBUG:
                print json_out

            json_out = json.loads(json_out)            
    
            sys.stdout.write("MAC Address on '%s': %s   \n" % (json_out['interface_name'],
                                                               get_color_out(the_str=json_out['fake_mac_address'],
                                                                             the_color='red',
                                                                             do_bold=False).strip()
                                                               )
                             )
            while True:
                pass
            #sys.stdout.flush()
        except KeyboardInterrupt:
            print
            pass

    reset_mac(vals=json.dumps(json_out), api_logger=log)
