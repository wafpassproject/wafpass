#!/usr/bin/python3

# Name:         WAFPASS
# Purpose:      Analysing parameters with all payloads' bypass methods, aiming 
#               at benchmarking security solutions like WAF
# Author:       Hamed izadi - hamedizadi@gmail.com
# Created:      09/02/2017
# Copyright:    (c) 2017 hamedizadi
# Licence:      Free to use, Only for research and do not use it for illegal purposes!
# Version:      1.0


from collections import Counter
from urllib.parse import urlparse
from random import sample
import requests.exceptions
import requests
import argparse
import operator
import sys
import time

def main():
    parser = argparse.ArgumentParser(description='WAFPASS.py - Analysing parameters with all payloads\' bypass methods, aiming at benchmarking security solutions like WAF. by Hamed Izadi @hezd')
    required = parser.add_argument_group('required arguments')
    required.add_argument('-u', '--url', help='Target URL (http://www.example.com/page.php?parameter=value)', required=True)
    parser.add_argument('-a', '--useragent', help='Set custom user-agent string')
    parser.add_argument('-d', '--delay', help='Set delay between requests (secends)', type=float)
    parser.add_argument('-r', '--randip', action='store_true', help='Random IP for X-Forwarded-For')
    parser.add_argument('-x', '--proxy', help='Set proxy (https://IP:PORT)')
    parser.add_argument('-p', '--post', help='Data string to be sent through POST (parameter=value&also=another)')
    parser.add_argument('-c', '--cookie', help='HTTP Cookie header')
    if len(sys.argv)==1: parser.print_help(); sys.exit(0)
    args = parser.parse_args()


    bla = """


                                                                
            ██╗    ██╗ █████╗ ███████╗██████╗  █████╗ ███████╗███████╗
            ██║    ██║██╔══██╗██╔════╝██╔══██╗██╔══██╗██╔════╝██╔════╝
            ██║ █╗ ██║███████║█████╗  ██████╔╝███████║███████╗███████╗
            ██║███╗██║██╔══██║██╔══╝  ██╔═══╝ ██╔══██║╚════██║╚════██║
            ╚███╔███╔╝██║  ██║██║     ██║     ██║  ██║███████║███████║
             ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝
                         
        WAFPASS - Analysing parameters with all payloads' bypass methods, aiming at benchmarking security solutions like WAF.
                      Copyright (c) 2017 Hamed Izadi (@hezd). 

        


    """
    print (bla)

    url = args.url
    print ("  URL: ", url)
    base_url = "bla"
    param_list = {}
    proxies = {}
    sum_req_succ = 0
    sum_req_succ = 0
    des = 0
    headers = {}


    parsed_uri = urlparse(url)
    domain = '{uri.scheme}://{uri.netloc}/'.format(uri=parsed_uri)


    if (len(url) - (len(domain) - 1)) == 0:
        url = domain
 
    #Proxy
    if args.proxy:
        if "https" in args.proxy[:5]:
            proxies['https'] = args.proxy
        elif "http" in args.proxy[:4]:
            proxies['http'] = args.proxy
        else:
            print ("\r\n\tSomething wrong with proxy, please Check WAFPASS usage!!!\r\n")
            sys.exit()
    #Proxy

    #Randomip
    def randomIP():
        numbers = []
        while not numbers or numbers[0] in (10, 172, 192):
            numbers = sample(range(1, 255), 4)
        return '.'.join(str(_) for _ in numbers)
    #Randomip
    
    #Headers
    if args.useragent:
        headers['user-agent'] = args.useragent
    else:
        headers['user-agent'] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/55.0.2883.87 Safari/537.36"
    if args.randip:
        headers['X-Forwarded-For'] = randomIP()
    if args.cookie:
        headers['cookie'] = args.cookie
    #Headers

    #upordown
    try:
        r = requests.head(domain, proxies=proxies, headers=headers, timeout=20)
        r.raise_for_status()
    except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
        print ("\r\nTarget appears to be down!!\r\n")
        sys.exit()
    #upordown

    #Header-cheking
    header_changed = 0
    req_header = requests.head(url,headers=headers, proxies=proxies, timeout=10)
    req_header_attack = requests.head(url, params={'test': '%00'}, headers=headers, proxies=proxies, timeout=10)
    if req_header_attack.status_code == req_header.status_code:
        if len('/'.join(req_header.headers.values())) != len('/'.join(req_header_attack.headers.values())):
            print ("\r\n\tThe server header is different when an attack is detected.\r\n")
            header_changed = 1
    #Header-cheking




    if not args.post:
        if "?" in url:
            des = 1
            urls = url.split("&")
            c = len(urls)
            part_1 = urls[0].split("?")
            base_url = part_1[0]
            del urls[0]
        else:
            urls = url.split("/")
            base_url = domain
            del urls[0:3]


    if args.post:
        paramp = args.post.split("&")


    def parameters_equal (arg):
        s_arg=arg.split("=")
        param_list[s_arg[0]] = s_arg[1]
        return;

    def parameters_slash (arg,param_count):
        param_list["param_"+str(param_count)] = arg
        return;

    if not args.post:
        if des == 1:
            parameters_equal(part_1[1])
            for url in urls:
                parameters_equal(url)
        else:
            param_count = 1
            for url in urls:
                parameters_slash(url, param_count)
                param_count = param_count + 1


    if args.post:
        for param in paramp:
            parameters_equal(param)

    #PayloadstoDic
    f = open('payloads/payloads.csv', 'r')
    payloads = {}
    for line in f:
        param_split = line.rpartition('@')
        payloads[param_split[0]] = param_split[2]
    #PayloadstoDic

    for name_m, value_m in param_list.items():
        print ("\r\n<Parameter Name> " , name_m , "\r\n")

        params = {}
        rs = []
        q = ""
        c = 0
        trycount = 0
        succ = 0
        fai = 0

        for payload, string in payloads.items():
            c = c + 1
            if args.delay:
                time.sleep(args.delay)
            name_m = str(name_m)
            value_m = str(value_m)
            if (payload[:1] == "\'") or (payload[:1] == "\""):
                param_list[name_m] = value_m+payload
            else:
                param_list[name_m] = value_m+"\" "+payload




            #Send-Request
            for i in range(3):
                try:
                    if args.post:
                        req = requests.post(url, data=param_list, headers=headers, proxies=proxies, timeout=10)
                    else:
                        if des == 1:
                            req = requests.get(base_url, params=param_list, headers=headers, proxies=proxies, timeout=10)
                        else:
                            base_url = domain
                            base_url = base_url + '/'.join(param_list.values())
                            req = requests.get(base_url, headers=headers, proxies=proxies, timeout=10)
                            base_url = domain
                    r.raise_for_status()
                    if (str(req.status_code)[0] == "2") or (str(req.status_code)[0] == "1") or (req.status_code == 404):
                        if not ((req.status_code == req_header_attack.status_code) and (int(len('/'.join(req.headers.values())) - int(len(req.headers.get('content-type')))) == len('/'.join(req_header_attack.headers.values()))) and (header_changed == 1)):
                            string = string[:-1]
                            print (" ✔ [", string, "][", payload,"] --> "  , "<successful> Response Status: "+str(req.status_code)+"\n\r", end="")
                            succ = succ + 1
                        else:
                            print ("   [", payload,"] --> "  , "<Failed> Response Status: "+str(req.status_code)+" *Header changed!\n\r", end="")
                            fai = fai + 1    
                    else:
                        print ("   [", payload,"] --> "  , "<Failed> Response Status: "+str(req.status_code)+"\n\r", end="")
                        fai = fai + 1           

                except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
                    print (" Retrying ... [ ", payload, " ]")
                    trycount = trycount + 1
                    continue
                else:
                    break    
            else:
                print (" Skipping ... [ ", payload, " ]")
                continue

            rs.append(req.status_code) 
            if trycount > 50:
                print ("\r\nSorry dude!, Check your internet connection or it appears you have been blocked!!!!!\r\nYou can use delay for the next try.")   
                sys.exit()         
            #Send-Request
            param_list[name_m] = value_m


        #Summary
        print ("   [ done ]")


        sum_req_succ = rs.count(200) + rs.count(404)
        print ("\r\n Summary \"" , name_m , "\":\r\n\r\n")
        sum_req_fai = rs.count(500) + rs.count(403) + rs.count(301) + rs.count(400) + rs.count(503) + rs.count(302)


        print ("   *Number of Requests: ", c, "\n\r\n\r", end="")
        count_err = Counter(rs)
        print ("       http response code = quantity")
        for err, err_count in count_err.items():
            print ("      ",err, " = ", err_count, "\r\n")
        print ("      + Successful:", succ, "\n\r", end="")
        print ("      x Failed:", fai, "\n\r", end="")
        print ("      - No response:", c - (fai+succ), "\n\r\n\r\n\r", end="")   
        #Summary


    sum_req_succ = sum_req_succ / len(param_list)
    sum_req_fai = sum_req_fai / len(param_list)
 
    if sum_req_succ >=100:
        print ("\n\r\n\r   ***No WAF detected!!!!!!\n\r")
    if sum_req_fai >=100:
        print ("\n\r\n\r   ***The target seems to be behind a WAF\n\r")


if __name__ == '__main__':
    main()
