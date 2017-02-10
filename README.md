# WAFPASS

                                                                
                            ██╗    ██╗ █████╗ ███████╗██████╗  █████╗ ███████╗███████╗
                            ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
                            ██║ █╗ ██║███████║█████╗  ██████╔╝███████║███████╗███████╗
                            ██║███╗██║██╔══██║██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
                            ╚███╔███╔╝██║  ██║██║     ██║     ██║  ██║███████║███████║
                             ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                         
                                WAFPASS - Copyright (c) 2017 Hamed Izadi (@hezd). 

        

WAFPASS Analysing parameters with all payloads' bypass methods, aiming at benchmarking security solutions like WAF.


   Today a great number of website owners around the globe use “Web Application Firewalls” to improve their security. However, these security applications suffer from many deficits such as poor performance, lack of updates, and so forth. Thus, they are hindered from working effectively against everyday attacks that are equipped with cutting edge technological innovations. This vulnerability can cause various issues and even lead to security failures.
   
   WAFPASS’s ultimate goal is to present a solution for promoting security systems like WAF in addition to providing a general overview of the security solutions.  
   
   


## Requirements:
  Python version 3.4.x is required for running this program.



## Disclaimer:
  This tool is only for testing and academic purposes and can only be used where strict consent has been given. Do not use it   for illegal purposes!


## Installation:
  Download WAFPASS by cloning the Git repository:
  
      $ git clone https://github.com/wafpassproject/wafpass.git


## Supported Platforms:

    Linux
    Mac OS X
    Windows (experimental)


## Usage:

  To get a list of all options and switches use:
  
      $ python3 wapfass.py
      
            
      usage: wafpass.py3 -u URL [-a USERAGENT] [-d DELAY] [-r] [-x PROXY] [-p POST] [-c COOKIE]

optional arguments:
  -a USERAGENT, --useragent USERAGENT      Set custom user-agent string
  -d DELAY, --delay DELAY                  Set delay between requests (secends)
  -r, --randip                             Random IP for X-Forwarded-For
  -x PROXY, --proxy PROXY                  Set proxy (https://IP:PORT)
  -p POST, --post POST                     Data string to be sent through POST (parameter=value&also=another)
  -c COOKIE, --cookie COOKIE               HTTP Cookie header

required arguments:
  -u URL, --url URL                        Target URL (http://www.example.com/page.php?parameter=value)
   
   
   
   
  You can add your payloads in /payloads/payloads.csv like this:
  
      payload@description
      
## Support:

    WAFPASS is the project of many hours of work and total personal dedication.

## Questions?

Contact [me](mailto:hamedizadi@gmail.com)
 
