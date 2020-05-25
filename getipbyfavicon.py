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

def getfilehash(filename):
    f=open(filename,'r')
    hash=mmh3.hash(f.read().encode('base64'))
    print("http.favicon.hash:{}".format(hash))
def queryshodan(url):
    o = urlparse(url)
    if len(o.path)>=2:
        url = url
    else:
        url = url+"/favicon.ico"
    try:
        hash = getfaviconhash(url)
        print("http.favicon.hash:{}".format(hash))
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
                        help="the favicon.ico website url,example:http://www.baidu.com/")
    parser.add_argument("-f", "--file",metavar='file',
                        help="the favicon.ico ")
    passargs = parser.parse_args()
    if passargs.url:
        queryshodan(passargs.url)
    if passargs.file:
        getfilehash(passargs.file)


if __name__ == '__main__':
    print(LOGO)
    main()
