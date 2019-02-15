
# Get ip by ico

[![Python 2.7](https://img.shields.io/badge/python-2.7-yellow.svg)](https://www.python.org/) [![License](https://img.shields.io/badge/license-GPLv2-red.svg)](https://raw.githubusercontent.com/Ridter/get_ip_by_ico/master/LICENSE) [![Twitter](https://img.shields.io/badge/twitter-@evi1cg-blue.svg)](https://twitter.com/evi1cg)

通过shodan的icon hash来检索同模板或同公司网站ip。

## Usage
```
usage: get_ip_by_ico.py [-h] -u url

Get ip list which using the same favicon.ico from shodan

optional arguments:
  -h, --help         show this help message and exit
  -u url, --url url  the favicon.ico website url,example:http://www.baidu.com/
```

## Example:
```
python get_ip_by_ico.py -u https://www.bilibili.com/

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

[+] Try to get 62 ip.
[+] Get ip: 61.244.33.181
[+] Get ip: 36.255.222.157
[+] Get ip: 61.244.33.182
[+] Get ip: 164.52.50.250
[+] Get ip: 107.150.117.242
[+] Get ip: 148.153.35.66
[+] Get ip: 148.153.45.10
[+] Get ip: 39.105.217.198
[+] Get ip: 212.64.58.165
[+] Get ip: 148.153.38.118
[+] Get ip: 87.245.210.8
[+] Get ip: 87.245.210.11
[+] Get ip: 87.245.210.7
[+] Get ip: 87.245.210.76
[+] Get ip: 87.245.210.77
[+] Get ip: 203.205.224.27
[+] Get ip: 203.205.224.16
[+] Get ip: 203.205.224.14
[+] Get ip: 203.205.224.26
[+] Get ip: 119.29.27.25
[+] Get ip: 148.153.45.166
[+] Get ip: 149.28.116.251
[+] Get ip: 104.24.121.228
[+] Get ip: 185.225.139.191
[+] Get ip: 106.75.217.188
[+] Get ip: 45.76.51.210
[+] Get ip: 104.232.100.138
[+] Get ip: 121.41.45.200
[+] Get ip: 104.232.100.139
[+] Get ip: 39.106.145.14
[+] Get ip: 120.78.71.93
[+] Get ip: 47.52.197.68
[+] Get ip: 47.98.166.128
[+] Get ip: 104.232.100.152
[+] Get ip: 116.62.228.209
[+] Get ip: 47.92.72.26
[+] Get ip: 198.13.56.92
[+] Get ip: 47.98.189.125
[+] Get ip: 153.122.121.149
[+] Get ip: 101.71.54.163
[+] Get ip: 103.73.161.228
[+] Get ip: 39.108.102.105
[+] Get ip: 104.243.141.225
[+] Get ip: 101.37.115.2
[+] Get ip: 47.52.173.32
[+] Get ip: 149.129.66.189
[+] Get ip: 121.46.231.67
[+] Get ip: 13.211.191.116
[+] Get ip: 188.131.153.141
```