#!/usr/bin/env python
# -*- coding: UTF-8 -*-
import mmh3
import requests
import argparse
from urlparse import urlparse
from shodan import Shodan
import base64


api = Shodan('YOUR-SHODAN-API-KEY')

LOGO = R"""
  ▄████ ▓█████▄▄▄█████▓ ██▓ ██▓███   ▄▄▄▄ ▓██   ██▓ ██▓ ▄████▄   ▒█████  
 ██▒ ▀█▒▓█   ▀▓  ██▒ ▓▒▓██▒▓██░  ██▒▓█████▄▒██  ██▒▓██▒▒██▀ ▀█  ▒██▒  ██▒
▒██░▄▄▄░▒███  ▒ ▓██░ ▒░▒██▒▓██░ ██▓▒▒██▒ ▄██▒██ ██░▒██▒▒▓█    ▄ ▒██░  ██▒
░▓█  ██▓▒▓█  ▄░ ▓██▓ ░ ░██░▒██▄█▓▒ ▒▒██░█▀  ░ ▐██▓░░██░▒▓▓▄ ▄██▒▒██   ██░
░▒▓███▀▒░▒████▒ ▒██▒ ░ ░██░▒██▒ ░  ░░▓█  ▀█▓░ ██▒▓░░██░▒ ▓███▀ ░░ ████▓▒░
 ░▒   ▒ ░░ ▒░ ░ ▒ ░░   ░▓  ▒▓▒░ ░  ░░▒▓███▀▒ ██▒▒▒ ░▓  ░ ░▒ ▒  ░░ ▒░▒░▒░ 
  ░   ░  ░ ░  ░   ░     ▒ ░░▒ ░     ▒░▒   ░▓██ ░▒░  ▒ ░  ░  ▒     ░ ▒ ▒░ 
░ ░   ░    ░    ░       ▒ ░░░        ░    ░▒ ▒ ░░   ▒ ░░        ░ ░ ░ ▒  
      ░    ░  ░         ░            ░     ░ ░      ░  ░ ░          ░ ░  
                                          ░░ ░         ░                                                          
"""


def getfaviconhash(url):
    try:
        response = requests.get(url)
        if response.headers['Content-Type'] == "image/x-icon":
            favicon = response.content.encode('base64')
            hash = mmh3.hash(favicon)
        else:
            hash = None
    except:
        print("[!] Request Error")
        hash = None
    return hash


def queryshodan(url):
    o = urlparse(url)
    if len(o.path)>=2:
        url = url
    else:
        url = url+"/favicon.ico"
    try:
        hash = getfaviconhash(url)
        if hash:
            query = "http.favicon.hash:{}".format(hash)
            count = api.count(query)['total']
            if count == 0:
                print("[-] No result")
            else:
                print("[+] Try to get {} ip.".format(count))
                for hosts in api.search_cursor(query):
                    print("[+] Get ip: "+hosts['ip_str'])
        else:
            print("[!] No icon find.")
    except Exception:
        print("[!] Invalid API key")
    except KeyboardInterrupt, e:
        print("[*] Shutting down...")


def main():
    parser = argparse.ArgumentParser(
        description='Get ip list which using the same favicon.ico from shodan')
    parser.add_argument("-u", "--url", metavar='url',
                        help="the favicon.ico website url,example:http://www.baidu.com/", required=True)
    passargs = parser.parse_args()
    queryshodan(passargs.url)


if __name__ == '__main__':
    print(LOGO)
    main()
