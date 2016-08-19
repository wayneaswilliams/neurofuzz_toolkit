"""
    Author: Andres Andreu < andres at neurofuzzsecurity dot com >
    Company: neuroFuzz, LLC
    Date: 7/25/2016
    Last Modified: 8/18/2016
    
    returns random values to be used as User-Agent ID strings

    BSD 3-Clause License
    
    Copyright (c) 2016, Andres Andreu, neuroFuzz LLC
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
from random import choice

def get_rand_user_agent():
    ''' Returns a randomly chosen value to be used as the User-Agent '''
    # pool of User-Agent headers to choose from
    headers = ['Googlebot/2.1 (http://www.googlebot.com/bot.html)',
               
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows NT)',
               'Mozilla/4.0 (compatible; MSIE 5.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; MSN 2.5; Windows 98)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 1.0.3705; .NET CLR 1.1.4322; Media Center PC 4.0; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; en) Opera 8.50',
               'Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.2; SV1; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; SV1; Arcor 5.005; .NET CLR 1.0.3705; .NET CLR 1.1.4322)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; YPC 3.0.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.1; .NET CLR 1.1.4322; .NET CLR 2.0.50727; .NET CLR 3.0.04506.30)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Win32)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 5.1)',
               'Mozilla/4.0 (compatible; MSIE 7.0b; Windows NT 6.0)',
               'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; Trident/4.0)',
               
               'Mozilla/5.0 (compatible)',
               'Mozilla/5.0 (compatible; Konqueror/2.2.2; Linux 2.4.14-xfs; X11; i686)',
               'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
               'Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0; Xbox)',
               'Mozilla/5.0 (compatible; MSIE 9.0; Windows Phone OS 7.5; Trident/5.0; IEMobile/9.0)',
               'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0)',
               'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; Trident/6.0; Xbox; Xbox One)',
               'Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch)',
               'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',

               'Mozilla/5.0 (Windows NT 5.1; U; en) Opera 8.50',
               'Mozilla/5.0 (Windows NT 6.2; rv:12.0) Gecko/20100101 Firefox/12.0',
               'Mozilla/5.0 (Windows NT 6.2; rv:12.0) Gecko/20100101 Firefox/23.0',
               'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/536.5 (KHTML, like Gecko) Chrome/19.0.1084.52 Safari/536.5',
               'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36',
               'Mozilla/5.0 (Windows NT 6.2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/28.0.1500.95 Safari/537.36 OPR/15.0.1147.153',
               'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',
               'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko/20100101 Firefox/12.0',
               'Mozilla/5.0 (Windows NT 6.3; Trident/7.0; .NET4.0E; .NET4.0C; rv:11.0) like Gecko',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.2) Gecko/20070219 Firefox/2.0.0.2',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.7.10) Gecko/20050716 Firefox/1.0.6',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.8.1.1) Gecko/20061204 Firefox/2.0.0.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; en-GB; rv:1.8.0.1) Gecko/20060111 Firefox/1.5.0.1',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl; rv:1.8) Gecko/20051107 Firefox/1.5',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; nl-NL; rv:1.7.5) Gecko/20041202 Firefox/1.0',
               'Mozilla/5.0 (Windows; U; Windows NT 5.1; ru; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US) AppleWebKit/525.13 (KHTML, like Gecko) Chrome/0.2.149.29 Safari/525.13',
               'Mozilla/5.0 (Windows; U; Windows NT 6.0; en-US; rv:1.8.0.4) Gecko/20060508 Firefox/1.5.0.4',
               'Mozilla/5.0 (Windows; U; Windows NT 6.1; ru; rv:1.9.2.3) Gecko/20100401 Firefox/4.0 (.NET CLR 3.5.30729)',

               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.8) Gecko/20050511',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.7.9) Gecko/20050711 Firefox/1.0.5',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.2) Gecko/20060308 Firefox/1.5.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.3) Gecko/20060426 Firefox/1.5.0.3',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.0.6) Gecko/20060808 Fedora/1.5.0.6-2.fc5 Firefox/1.5.0.6 pango-text',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2)',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070220 Firefox/2.0.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.8.1.2) Gecko/20070221 SUSE/2.0.0.2-6.1 Firefox/2.0.0.2',
               'Mozilla/5.0 (X11; U; Linux i686; cs-CZ; rv:1.7.12) Gecko/20050929',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.8.1.9) Gecko/20071025 Firefox/2.0.0.9',
               'Mozilla/5.0 (X11; U; Linux i686 (x86_64); en-US; rv:1.9a1) Gecko/20061204 GranParadiso/3.0a1',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.8.1) Gecko/20060601 Firefox/2.0 (Ubuntu-edgy)',            
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.7) Gecko/20100809 Fedora/3.6.7-1.fc14 Firefox/3.6.7',
               'Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.2.8) Gecko/20100804 Gentoo Firefox/3.6.8',
               'Mozilla/5.0 (X11; U; FreeBSD i386; en-US; rv:1.7.8) Gecko/20050609 Firefox/1.0.4',

               'Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.0.7) Gecko/20060909 Firefox/1.5.0.7',
               'Mozilla/5.0 (Macintosh; U; PPC Mac OS X Mach-O; en-US; rv:1.7.12) Gecko/20050915 Firefox/1.0.7',
               
               'Mozilla/5.0 (iPhone; U; CPU like Mac OS X; en) AppleWebKit/420+ (KHTML, like Gecko) Version/3.0 Mobile/1A543 Safari/419.3',
               'Mozilla/5.0 (iPad; CPU OS 6_0 like Mac OS X) AppleWebKit/536.26 (KHTML, like Gecko) Version/6.0 Mobile/10A5355d Safari/8536.25',
               
               "Windows-RSS-Platform/1.0 (MSIE 7.0; Windows NT 5.1)",
               "Windows NT 6.0 (MSIE 7.0)",
               "Windows NT 4.0 (MSIE 5.0)",             
               
               "Opera/6.x (Windows NT 4.0; U) [de]",
               "Opera/7.x (Windows NT 5.1; U) [en]",
               'Opera/8.0 (X11; Linux i686; U; cs)',
               'Opera/8.51 (Windows NT 5.1; U; en)',
               'Opera/9.0 (Windows NT 5.1; U; en)',
               'Opera/9.01 (X11; Linux i686; U; en)',
               'Opera/9.02 (Windows NT 5.1; U; en)',
               'Opera/9.10 (Windows NT 5.1; U; en)',
               "Opera/9.20 (Windows NT 6.0; U; en)",
               'Opera/9.23 (Windows NT 5.1; U; ru)',

               "YahooSeeker/1.2 (compatible; Mozilla 4.0; MSIE 5.5; yahooseeker at yahoo-inc dot com ; http://help.yahoo.com/help/us/shop/merchant/)",
               
               ]
    return choice(headers)

