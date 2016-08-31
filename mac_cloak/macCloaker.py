"""
    Author:     Andres Andreu
    Contact:    <andres [at] neurofuzzsecurity dot com>
    Company:    neuroFuzz, LLC
    Date:       6/23/2012
    Modified:   8/19/2016
    
    This software runs on certain flavors of Linux and Mac OSX (written on 10.7.x with python 2.6/2.7). 
    Its intent is to temporarily change/spoof the MAC Address on the machine running it. Note that you 
    will need to be on the machine locally, not a remote shell as you will kill your own session.
    
    It leverages macchanger if it is found but works just as well without it. I happen
    to think macchanger is great software so props to Alvaro Lopez Ortega <alvaro [at] alobbs dot com>
    for writing it (http://www.alobbs.com/macchanger). But I needed something a little more automated 
    and that could be used as an API from other py progs while conducting security audit work and/or
    pen testing stuff.
    
    The code I did see out there that operates on this same functionality just lacked so much and made so many static
    and bad assumptions that I decided to just write this myself. So in the spirit of open source I am sharing this
    with the world.
    
    this is intended to be used via the API's:
    
    cloak_mac(staticval='', api_logger='', verbose=True)
    reset_mac(vals={}, api_logger='')
    
    example:
    
    ...
    json_out = cloak_mac(staticval=staticval, api_logger=log, verbose=True)
    ...
    do your thing
    ...
    reset_mac(vals=json.dumps(json_out), api_logger=log)
    ...
    
    
    If WRITEDAT is set to True it stores a record of your MAC Address activity with
    this tool in a file called: ".originalMac", the data in there is structured as such:
    
        interface tab MAC_Address tab #pid#date/time_stamp
    
    where the pid is that of the prog run when that change
    was made. An example:
    
        eth0    07:c8:6f:23:32:f0    #764#2012-06-25T23:49:15.405275
        
    *** CAVEAT: currently some wireless adaptors do not enjoy this
    process and this process may fail. I will fix that when I have
    some time. Or maybe someone else steps up and does this. ***
    
    Some errors to be aware of when messing with MAC Addresses:
    
    SIOCSIFHWADDR: Operation not supported

    indicates that the hardware address for the specified interface cannot be changed.
    This could be because the interface does not have a hardware address, or because
    the ability to change the address has not been implemented by the relevant device driver.

    SIOCSIFHWADDR: Cannot assign requested address

    probably indicates that the requested MAC address is not a unicast address.
    (To qualify as a unicast address the first byte must be even.)

    SIOCSIFHWADDR: Device or resource busy - you may need to down the interface

    probably indicates that the relevant device driver does not allow the MAC 
    address to be changed while the interface is up.
    
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
    TODO
    
    - macchanger static mac address
    - run on a timer - constantly change mac address
    - determine dhclient version (some dont support timeout)
    
    ************** ChangeLog ***********************************************
    2.0.1 - 5/5/2016
    
        - changed internal output of prog to user logging object
        - added color output functionality
        - changed DHCP handling from trying to detect usage to just defaulting to True (DHCP in use)
        - added API entry points
        - added JSON return value from the cloak API
        - added support for the setting of a specific (static) MAC address

    ************** ChangeLog ***********************************************
"""
import os
import fnmatch
import signal
import commands
import sys
import random
import subprocess
import re
import datetime
import time
import platform
import getopt
import json
import logging
import logging.config

__version__ = "2.0.1"
###############################################
DEBUG = False
#DEBUG = True
WRITEDAT = True

LINUX = "linux"
DARWIN = "darwin"
IFCONFIG = "ifconfig"
MACCHANGER = "macchanger"
DHCLIENT = "dhclient"
ORIGINALMACFILE = ".originalMac"
SHIT_MSG = "This shit didnt work"
###############################################
#non-class funcs

def validate_mac_address_format(the_mac=''):
    ''' '''
    if the_mac:
        if re.match("[0-9a-f]{2}([-:])[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", the_mac.lower()):
            return True
    return False


def which(program=""):
    ''' find location of executable code '''
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
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            for candidate in ext_candidates(exe_file):
                if is_exe(candidate):
                    return candidate
    return None


def find_file(pattern="", root='/'):
    ''' '''
    if DEBUG:
        print "Searching for ... %s" % pattern
    matches = []

    for path, dirs, files in os.walk(os.path.abspath(root)):
        for filename in fnmatch.filter(files, pattern):
            matches.append(os.path.join(path, filename))
 
    return matches


def am_i_root():
    ''' checks to see if running user has root privileges '''
    if os.geteuid() != 0:
        print("You need to be root to do this ...")
        return False
    else:
        return True


def read_file(fhandle=""):
    ''' '''
    fcontent = ''
    try:
        f = open(fhandle, 'r')
        fcontent = f.readlines()
        f.close()
        return fcontent
    except Exception, e:
        print e
        
        
def discover_platform():
    ''' calculates string identifying the running OS '''
    theos = platform.uname()[0].lower()
    un = platform.platform().lower()  
    if theos == LINUX:
        if 'fedora' in un:
            return (theos, 'fedora')
        if 'debian' in un:
            return (theos, 'debian')
        if 'ubuntu' in un:
            return (theos, 'ubuntu')
    if theos == DARWIN:
        return (theos, un)
    
    
def shut_down(s=""):
    ''' output and program shutdown '''
    print "\n%s, shutting down ...\n" % s
    sys.exit(0)
    
    
def run_os_process(lParams=[]):
    ''' run system level processes '''
    co = subprocess.Popen(lParams, stdout = subprocess.PIPE)
    return co.stdout.read().split()


def get_color_out(the_str='', the_color='', do_bold=False):
    ''' '''
    l_color = the_color.lower()
    
    bold_tmpl = '\033[1;%sm%s\033[1;m'
    non_bold_tmpl = '\033[0;%sm%s\033[0;m'
    
    if l_color == 'gray':
        if do_bold:
            return bold_tmpl % ('30',the_str)
        else:
            return non_bold_tmpl % ('30',the_str)
    elif l_color == 'red':
        if do_bold:
            return bold_tmpl % ('31',the_str)
        else:
            return non_bold_tmpl % ('31',the_str)
    elif l_color == 'green':
        if do_bold:
            return bold_tmpl % ('32',the_str)
        else:
            return non_bold_tmpl % ('32',the_str)
    elif l_color == 'yellow':
        if do_bold:
            return bold_tmpl % ('33',the_str)
        else:
            return non_bold_tmpl % ('33',the_str)
    elif l_color == 'blue':
        if do_bold:
            return bold_tmpl % ('34',the_str)
        else:
            return non_bold_tmpl % ('34',the_str)
    elif l_color == 'magenta':
        if do_bold:
            return bold_tmpl % ('35',the_str)
        else:
            return non_bold_tmpl % ('35',the_str)
    elif l_color == 'cyan':
        if do_bold:
            return bold_tmpl % ('36',the_str)
        else:
            return non_bold_tmpl % ('36',the_str)
    elif l_color == 'white':
        if do_bold:
            return bold_tmpl % ('37',the_str)
        else:
            return non_bold_tmpl % ('37',the_str)
    elif l_color == 'crimson':
        if do_bold:
            return bold_tmpl % ('38',the_str)
        else:
            return non_bold_tmpl % ('38',the_str)
    else:
        return the_str
###############################################
"""
APP_META = {'app_name':get_color_out(the_str='[neuroFuzz security macCloaker] - ', the_color='white', do_bold=False)}

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
"""
###############################################

class MacCloak(object):

    # constructor
    def __init__(self, logger=None):
        self.targetInterface = ""
        self.originalMacAddress = ""
        self.fakeMacAddress = ""
        self.persistFile = ORIGINALMACFILE
        self.lineFormatString = '%s\t%s\t#%d#%s\n'
        self.defaultProg = which(program=IFCONFIG)
        
        self.runningPlatform, self.runningPlatformFlavor = discover_platform()
        '''
            5/5/2016 ...
            I am no longer trying to detect whether DHCP is in use
            or not. The overwhelming majority of stuff I encounter
            out in the field uses DHCP. And even if they dont calling
            dhclient on an interface that has a static address set to
            it seems benign.
        '''
        #self.dhcpUsed = False
        self.dhcpUsed = True
        
        self.logger = logger or log
        #self.logger = logger or logging.getLogger(__name__)
        #self.logger = self.set_logger()
        #self.logger = logger or get_logger_obj()
        
        self.macchanger = MACCHANGER
        self.macchanger_path = ''


    def set_interface(self, iface=""):
        ''' '''
        self.targetInterface = iface
    
        
    def get_interface(self):
        ''' '''
        return self.targetInterface
    
        
    def setOriginalMacAddress(self, mac=""):
        ''' '''
        if len(mac) == 17:
            self.originalMacAddress = mac
        if len(mac) == 16:
            self.originalMacAddress = '0' + mac


    def getOriginalMacAddress(self):
        ''' '''
        return self.originalMacAddress


    def set_fake_mac_address(self, val=""):
        ''' '''
        if len(val) == 17:
            self.fakeMacAddress = val
        if len(val) == 16:
            self.fakeMacAddress = '0' + val


    def get_fake_mac_address(self):
        ''' '''
        return self.fakeMacAddress


    def getRunningPlatform(self):
        ''' fetches lowercase string identifying the running OS '''
        return self.runningPlatform


    def getRunningPlatformFlavor(self):
        ''' fetches string identifying more granular aspects of a Linux OS '''
        return self.runningPlatformFlavor


    def randomMAC(self):
        ''' generates random MAC Address '''
        
        """
            sometimes we run into this error, especially
            on Ubuntu hosts for some strange reason:
            
                SIOCSIFHWADDR: Cannot assign requested address

            probably indicates that the requested MAC address is not a unicast address.
            To qualify as a unicast address the first byte must be even.
            
            A crazy regex to check for this is:
            
            ^[a-fA-F0-9][aceACE02468][:|\-]?([a-fA-F0-9]{2}[:|\-]?){4}[a-fA-F0-9]{2}$
            
            so my original function has to be modified ...

        mac = [random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff) , 
               random.randint(0x00, 0xff)]
        return (':'.join(map(lambda x: "%02x" % x, mac)))
        """
        firstByte = "0x0" + random.choice('aceACE02468')
        mac = [ #0x00,
               int(firstByte, 16),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff),
               random.randint(0x00, 0xff)]
        return ':'.join(map(lambda x: "%02x" % x, mac))


    def modMac(self, randomly=False, staticval='', reset=False, do_output=False):
        ''' kicks off the change MAC Address process '''
        
        use_mac_changer = False
        '''
            cannot assume that macchanger will only
            exist in one location so let's look
            for it
        '''
        macchanger_pth = None
        macchanger_pth = which(program=self.macchanger)
        if macchanger_pth:
            if not reset and do_output:
                self.logger.info("MAC Changer is installed, using it...")
            use_mac_changer = True
            self.set_macchanger_path(the_path=macchanger_pth)
        else:
            if not reset and do_output:
                self.logger.info("MAC Changer is not installed, using ifconfig method!")

        if reset:
            if use_mac_changer:
                self.useMacchanger()
            else:
                self.useIfconfig(reset=True, do_output=do_output)
                
        if staticval:
            if use_mac_changer:
                # TODO - set macchanger to use static mac address
                self.useMacchanger()
            else:
                self.useIfconfig(staticval=staticval, do_output=do_output)               

        if randomly:
            if use_mac_changer:
                self.useMacchanger()
            else:
                self.useIfconfig(randomly=True, do_output=do_output)

            
    def modInterfaceState(self, thestate="up"):
        ''' modify interface state up/down '''
        if thestate == "down":
            run_os_process(lParams=[self.defaultProg, self.targetInterface, thestate])
        if thestate == "up":
            run_os_process(lParams=[self.defaultProg, self.targetInterface, thestate])


    def useMacchanger(self):
        ''' use macchanger to take action on the interface '''
        
        self.logger.info("Changing your original MAC address (%s) to something totally random...\n" % self.getOriginalMacAddress())
        #print("Changing your original MAC address (%s) to something totally random...\n" % self.getOriginalMacAddress())
        #macchanger = which(program=MACCHANGER)
        macchanger = self.get_macchanger_path()
        
        # Puts interface down
        self.modInterfaceState(thestate='down')
        if self.checkIfaceStateDown() == 1:

            # change the MAC Address
            poutput = run_os_process(lParams=[macchanger, "--random", self.targetInterface])
        
            self.set_fake_mac_address(val=poutput[poutput.index("Faked")+2])

            # Puts interface up
            self.modInterfaceState(thestate='up')
            if self.checkIfaceMacAddress(fake=True) == 1:
                if self.checkIfaceStateUp() == 1:
                    self.handleDhcpReset(do_output=do_output)
                    

    def useIfconfig(self, randomly=False, staticval='', reset=False, do_output=False):
        ''' use ifconfig to take action on the interface '''

        ''' reset back to normal '''
        if reset:
            '''
                this section sets the MAC Address back
                to its normal and original setting
            '''
            #print("Changing your MAC address to its original value ... %s") % self.originalMacAddress
            if do_output:
                self.logger.info("Changing your MAC address to its original value ... %s" % get_color_out(the_str=self.getOriginalMacAddress(), the_color='green'))
            # on Linux
            if self.getRunningPlatform() == LINUX:
                if self.processLinux(reset=True, do_output=do_output) == False:
                    shut_down(s="Process failed")
            # on Mac OSX 
            if self.getRunningPlatform() == DARWIN:
                if self.processDarwin(reset=True, do_output=do_output) == False:
                    shut_down(s="Process failed")
            return

        ''' either randomly or static '''
        if randomly == True:
            randVal = self.randomMAC()
            self.set_fake_mac_address(val=randVal)
            #print("Changing your original MAC address (%s) to something totally random...\n" % self.getOriginalMacAddress())
            if do_output:
                self.logger.info("Changing your original MAC address (%s) to '%s' ...\n" % (get_color_out(the_str=self.getOriginalMacAddress(), the_color='green'),
                                                                                            get_color_out(the_str='something totally random', the_color='red')
                                                                                            )
                                 )
            
            # on Linux - ifconfig en1 hw ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == LINUX:
                if self.processLinux(randVal=randVal, do_output=do_output) == False:
                    shut_down(s="Process failed")
            # on Mac OSX - ifconfig en1 ether 00:e2:e3:e4:e5:e6
            if self.getRunningPlatform() == DARWIN:
                if self.processDarwin(randVal=randVal, do_output=do_output) == False:
                    shut_down(s="Process failed")
        else:
            ''' this section sets the MAC Address to a static value '''
            self.set_fake_mac_address(val=staticval)
            #print("Changing your original MAC address (%s) to %s ...\n" % (self.getOriginalMacAddress(), staticval))
            if do_output:
                self.logger.info("Changing your original MAC address (%s) to '%s' ...\n" % (get_color_out(the_str=self.getOriginalMacAddress(), the_color='green'),
                                                                                            get_color_out(the_str=staticval, the_color='red')
                                                                                            )
                                 )

            # on Linux
            if self.getRunningPlatform() == LINUX:
                if self.processLinux(staticval=staticval, do_output=do_output) == False:
                    shut_down(s="Process failed")
            # on Mac OSX 
            if self.getRunningPlatform() == DARWIN:
                if self.processDarwin(staticval=staticval, do_output=do_output) == False:
                    shut_down(s="Process failed")
        
                
    def checkIfaceStateUp(self, do_output=False):
        ''' '''
        targ = 15
        cnt = 0
        while True:
            procOut = run_os_process(lParams=[self.defaultProg])            
            if self.targetInterface in procOut:
                if do_output:
                    self.logger.info("Interface is %s" % get_color_out(the_str='up', the_color='green'))
                return 1
            if cnt == targ:
                if do_output:
                    self.logger.info("Interface seems %s" % get_color_out(the_str='up', the_color='green'))
                return 1
            cnt += 1
        return 0


    def checkIfaceStateDown(self, do_output=False):
        ''' '''
        targ = 15
        cnt = 0
        while True:
            procOut = run_os_process(lParams=[self.defaultProg])
            if self.targetInterface in procOut:
                if do_output:
                    self.logger.info("Interface is %s" % get_color_out(the_str='up', the_color='green'))
                return 0
            if cnt == targ:
                if do_output:
                    self.logger.info("Interface seems %s" % get_color_out(the_str='down', the_color='red'))
                return 1
            cnt += 1
        return 0


    def checkIfaceMacAddress(self, fake=True, do_output=False):
        ''' '''
        time.sleep(5)
        targ = 5
        cnt = 0
        ret = 0
        while True:
            procOut = run_os_process(lParams=[self.defaultProg])
            if fake == True:
                if self.fakeMacAddress in procOut:
                    #print "MAC Address %s SET" % self.fakeMacAddress
                    if do_output:
                        self.logger.info("MAC Address %s SET" % get_color_out(the_str=self.fakeMacAddress, the_color='red'))
                    ret = 1
                    break
            else:
                if self.originalMacAddress in procOut:
                    #print "MAC Address %s SET" % self.originalMacAddress
                    if do_output:
                        self.logger.info("MAC Address %s SET" % get_color_out(the_str=self.originalMacAddress, the_color='green'))
                    ret = 1
                    break
            if cnt == targ:
                ret = 0
                break
            cnt += 1
        return ret


    def processLinux(self, randVal=None, staticval='', reset=False, do_output=False):
        ''' set MAC Address to some altered state on Linux'''
        # Puts interface down
        self.modInterfaceState(thestate='down')
        '''
            look for confirmation of interface
            being in a down state
        '''
        if self.checkIfaceStateDown(do_output=do_output) == 1:
            # alter MAC Address
            if randVal != None:
                run_os_process(lParams=[self.defaultProg, self.targetInterface, "hw", "ether", randVal])
            else:
                if staticval:
                    run_os_process(lParams=[self.defaultProg, self.targetInterface, "hw", "ether", staticval])                
                
            if reset:
                run_os_process(lParams=[self.defaultProg, self.targetInterface, "hw", "ether", self.originalMacAddress])

            '''
                look for confirmation of the new
                MAC Address being set in place
            '''
            # Puts interface up
            self.modInterfaceState(thestate='up')
            
            if randVal or staticval:
                if self.checkIfaceMacAddress(fake=True, do_output=do_output) == 1:
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return True
                else:
                    self.logger.info(SHIT_MSG)
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return False
                
            if reset:
                if self.checkIfaceMacAddress(fake=False, do_output=do_output) == 1:
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return True
                else:
                    self.logger.info(SHIT_MSG)
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return False


    def processDarwin(self, randVal=None, staticval='', reset=False, do_output=False):
        ''' set MAC Address to some altered state on Mac OSX '''
        # change the MAC Address
        if randVal != None:
            run_os_process(lParams=[self.defaultProg, self.targetInterface, "ether", randVal])
        else:
            if staticval:
                run_os_process(lParams=[self.defaultProg, self.targetInterface, "ether", staticval])                
            
        if reset:
            run_os_process(lParams=[self.defaultProg, self.targetInterface, "ether", self.originalMacAddress])

        time.sleep(2)
        # Puts interface down
        self.modInterfaceState(thestate='down')
        # Puts interface up
        if self.checkIfaceStateDown(do_output=do_output) == 1:
            self.modInterfaceState(thestate='up')
            
            if randVal or staticval:
                if self.checkIfaceMacAddress(fake=True, do_output=do_output) == 1:
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return True
                else:
                    self.logger.info(SHIT_MSG)
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return False
                
            if reset:
                if self.checkIfaceMacAddress(fake=False, do_output=do_output) == 1:
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return True
                else:
                    self.logger.info(SHIT_MSG)
                    if self.checkIfaceStateUp(do_output=do_output) == 1:
                        self.handleDhcpReset(do_output=do_output)
                    return False


    def persist_data(self):
        ''' save the current MAC Address data out to a file '''
        try:
            macs = open(self.persistFile, 'a')
            macs.write(self.lineFormatString % (self.targetInterface,
                                                self.originalMacAddress,
                                                os.getpid(), datetime.datetime.now().isoformat()))
            macs.close()
        except Exception, e:
            #print e
            self.logger.error(e)
            if 'denied' in str(e):
                self.logger.error("You do not have enough permissions to modify %s" % self.persistFile)


    def getIface(self, interface_name=''):
        """ extracts a list of system interfaces for user to choose from """
        theinterface = ""
        wecontinue = False

        if os.name == "posix":
            co = subprocess.Popen(self.defaultProg, stdout = subprocess.PIPE)
            ifconfig = co.stdout.read()
            thechoices = []
        
            if not interface_name:
                print "\nPick an interface to mess with:\n"

            if self.getRunningPlatform() == DARWIN:
                #thechoices = re.findall(r'^([\w]*):? [\w=<,>\s]*(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', ifconfig, re.MULTILINE)
                thechoices = re.findall(r'^([\w]*):? [\w=<,>\s]*(([0-9a-fA-F]{2}:?){6})', ifconfig, re.MULTILINE)
                if DEBUG:
                    print thechoices
            '''
                this regex was tested with Fedora and Debian ...
                not sure if it will actually work with every flavor of Linux
                
                this MAC regex: ([0-9a-fA-F]{2}:?){6} seemed good
                but gave way too many false positives on Linux
            '''
            if self.getRunningPlatform() == LINUX:
                if self.getRunningPlatformFlavor() == 'fedora':
                    thechoices = re.findall(r'^([\w]*): [\w=<,>:.\s]* ([a-f\d]{1,2}(?::[a-f\d]{1,2}){5})', ifconfig, re.MULTILINE)
                else:
                    thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})', ifconfig, re.MULTILINE)
                #thechoices = re.findall(r'^([\w]*):? [\w=<,>:.\s]*(([0-9a-fA-F]{2}:?){6})', ifconfig, re.MULTILINE)
                  
            '''
                if no interfaces are discovered then
                there is no need to go any further
            '''
            if thechoices != None:
                if not interface_name:
                    for f in thechoices:
                        if not f[1].endswith(":"):
                            print "%s %s" % (f[0], f[1])
            else:
                print "No interfaces discovered, help us out and send us this data via email ..."
                print "\n\n###########################"
                print ifconfig
                print "###########################\n"
                print "mail to: <support [at] neurofuzzsecurity dot com>\n\n"
                sys.exit(1)

            # interfaces discovered, get a choice        
            try:
                if not interface_name:
                    var = raw_input("\nYour choice: ")
                else:
                    var = interface_name
                
                # ensure choice is in range
                for f in thechoices:
                    if var == f[0]:
                        var = f
                        wecontinue = True
                        break
                
                if wecontinue:
                    self.set_interface(iface=var[0])
                    self.setOriginalMacAddress(mac=var[1])
                    if WRITEDAT:
                        self.persist_data()
                    # check to see if DHCP is used
                    #self.dhcpUsed = self.isDhcpUsed()
                    self.dhcpUsed = self.get_dhcp_used()
                else:
                    shut_down("Choice out of range")
            except ValueError, e:
                print e
                shut_down("Invalid input")
            except IndexError, e:
                print e
                shut_down("Invalid input")
        else:
            shut_down("Sorry but this is written to run on *nix platforms, grow up")


    """
    def isDhcpUsed(self):
        ''' tries to discover if DHCP is in use by the running host '''
        
        '''
            this turned out to be a real pain in the ass !!! Every flavor of Linux does
            things differently enough that I had to make this quasi platform specific.
            I don't like it but it works until I can figure out a better way.
        '''
        res = False
        dhcpterms = ['dhcp' ]
        thepattern = None
        # check to see if DHCP is enabled
        '''
            on Linux - DHCP config data is saved
            into config files so we have to hunt
            those down and sift through them
        '''
        if self.getRunningPlatform() == LINUX:
            '''
                fedora uses ifcfg-interface files,
                such as:
                
                ifcfg-eth0
                
                so look for those if fedora is the
                detected OS
            '''
            if self.getRunningPlatformFlavor() == 'fedora':
                thepattern = "ifcfg-" + self.targetInterface
                iface_file_handle = find_file(pattern=thepattern)[0]

            '''
                deb and ubuntu seem to both use the file:
                
                /etc/network/interfaces
            '''
            if self.getRunningPlatformFlavor() == 'debian' or \
                self.getRunningPlatformFlavor() == 'ubuntu':
                iface_file_handle = "/etc/network/interfaces"

            #print "Found file ... %s, reading its contents" % iface_file_handle
            self.logger.info("Found file ... %s, reading its contents" % iface_file_handle)
            fcontent = read_file(fhandle=iface_file_handle)
            for d in dhcpterms:
                for fc in fcontent:
                    if d in fc:
                        res = True

        '''
            on Mac - ipconfig getpacket en0
            any data back it means DHCP is used, otherwise
            there is no response
        '''
        if self.getRunningPlatform() == DARWIN:
            poutput = run_os_process(lParams=["ipconfig", "getpacket", self.targetInterface])
            if len(poutput) > 0:
                res = True

        return res
    """


    def get_dhcp_used(self):
        ''' '''
        return self.dhcpUsed


    def handleDhcpReset(self, do_output=False):
        ''' handle the DHCP client reset '''
        
        '''
            if dhcp is used then restart client ...
            if we only bring up the interface and dont renew dhclient lease then full
            network connectivity is not restored
            
            I am leaving the Linux DHCP restart outside of the conditional check on
            var dhcpUsed. The reason for this is that I had trouble deciphering DHCP
            use on some flavors of Linux. DHCP restarts on non-DHCP using interfaces
            don't seem to have an adverse effect. This is not clean but works for now. 
        '''
        if self.getRunningPlatform() == LINUX:
            dhclient = which(program=DHCLIENT)
            if dhclient:
                #print "On Linux ... running: %s" % dhclient
                if do_output:
                    self.logger.info("On Linux ... running: %s" % dhclient)
                run_os_process(lParams=[dhclient, "-r", "-timeout", "30"])
                time.sleep(5)
                run_os_process(lParams=[dhclient, "-timeout", "30", self.targetInterface])
            else:
                '''
                print "could not find an appropriate DHCP client,"
                print "make sure your networking still works at this point\n"
                '''
                if do_output:
                    self.logger.info("could not find an appropriate DHCP client, make sure your networking still works at this point\n")

        
        if self.dhcpUsed == True:
            # Linux

            if self.getRunningPlatform() == DARWIN:
                prog = "ipconfig"
                '''
                    Mac OSX
                    sudo ipconfig set en0 BOOTP
                    sudo ipconfig set en0 DHCP
                '''
                run_os_process(lParams=[prog, "set", self.targetInterface, "BOOTP"])
                time.sleep(2)
                run_os_process(lParams=[prog, "set", self.targetInterface, "DHCP"])
                
                
    def set_macchanger_path(self, the_path=''):
        ''' '''
        if the_path:
            self.macchanger_path = the_path
            
    def get_macchanger_path(self):
        ''' '''
        return self.macchanger_path
    


    
###############################################     
'''
    API
    
    JSON (dict) keys:

    - interface_name (str)
    - original_mac_address (str)
    - fake_mac_address (str)
    - dhcp_used (bool)
    - random_set (bool)
    - static_set (bool)
    - verbose (bool)
    
'''
def cloak_mac(interface_name='', staticval='', api_logger=None, verbose=False):
    ''' returns a JSON object with relevant meta-data '''

    ret = {}
    iface = None
    spoofmac = None
    
    if api_logger:
        spoofmac = MacCloak(logger=api_logger)
    else:
        spoofmac = MacCloak()
        api_logger = log
    
    '''
        if interface_name is populated then it is an
        API call as the entry point, if its our main
        calling this then fetch the interface from the
        user interactively ( spoofmac.getIface() )
    '''
    if interface_name:        
        # TODO check validity of the interface name
        # if valid ...
        spoofmac.getIface(interface_name=interface_name)
    else:
        spoofmac.getIface()
        
    
    if spoofmac:
        
        ret['verbose'] = verbose
        ret['interface_name'] = spoofmac.get_interface()
        #ret['interface_ix'] = 
        ret['original_mac_address'] = spoofmac.getOriginalMacAddress()
        if verbose and not interface_name:
            '''
            log.info("The Current MAC address on interface '%s' is: '%s'" % (get_color_out(the_str=spoofmac.get_interface(), the_color='green'),
                                                                             get_color_out(the_str=spoofmac.getOriginalMacAddress(), the_color='green')
                                                                             )
                     )
            '''
            api_logger.info("The Current MAC address on interface '%s' is: '%s'" % (get_color_out(the_str=spoofmac.get_interface(), the_color='green'),
                                                                                    get_color_out(the_str=spoofmac.getOriginalMacAddress(), the_color='green')
                                                                                    )
                            )

        #ret['dhcp_used'] = spoofmac.dhcpUsed
        ret['dhcp_used'] = True
        '''
        if verbose:
            api_logger.info("DHCP usage detection: %s" % spoofmac.get_dhcp_used())
        '''
        
        if am_i_root() == True:
            # no static value assumes random ...
            if not staticval:
                if verbose and not interface_name:
                    #log.info("Changing MAC Address to something random")
                    api_logger.info("Changing MAC Address to something random")

                if interface_name:
                    spoofmac.modMac(randomly=True)
                else:
                    spoofmac.modMac(randomly=True, do_output=True)
                    
                ret['random_set'] = True
            else:
                if verbose and not interface_name:
                    #log.info("Changing MAC Address to %s" % staticval)
                    api_logger.info("Changing MAC Address to %s" % staticval)

                if interface_name:
                    spoofmac.modMac(randomly=False, staticval=staticval)
                else:
                    spoofmac.modMac(randomly=False, staticval=staticval, do_output=True)
                
                ret['static_set'] = True
                
            ret['fake_mac_address'] = spoofmac.get_fake_mac_address()
            if verbose and not interface_name:
                #log.info("Your New MAC address is: %s\n\n" % get_color_out(the_str=spoofmac.get_fake_mac_address(), the_color='red'))
                api_logger.info("Your New MAC address is: %s\n\n" % get_color_out(the_str=spoofmac.get_fake_mac_address(), the_color='red'))

        else:
            shut_down(s="root privileges are necessary and dont seem to be available for this program run")
    else:
        shut_down(s="something went wrong during this program run")
            
    return json.dumps(ret)



def reset_mac(vals={}, api_logger=None):
    ''' '''
    
    if vals:
        j_vals = json.loads(vals) 
        if am_i_root() == True:
            if api_logger:
                spoofmac = MacCloak(logger=api_logger)
            else:
                spoofmac = MacCloak()

            spoofmac.set_interface(iface=j_vals['interface_name'])
            spoofmac.setOriginalMacAddress(mac=j_vals['original_mac_address'])
            spoofmac.modMac(randomly=False, staticval='', reset=True, do_output=True)
        else:
            shut_down(s="root privileges are necessary and dont seem to be available for this program run")
###############################################

    
