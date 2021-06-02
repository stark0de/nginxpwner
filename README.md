# Nginxpwner

<p align="center"><img src="https://i.postimg.cc/vm3LWFj4/nginxpwner.png" /></p>

Nginxpwner is a simple tool to look for common Nginx misconfigurations and vulnerabilities.

## Install:

```
cd /opt
git clone https://github.com/stark0de/nginxpwner
cd nginxpwner
chmod +x install.sh
./install.sh
```

## Install using Docker
```
git clone https://github.com/stark0de/nginxpwner
cd nginxpwner
sudo docker build -t nginxpwner:latest .
```

Run the image
```
sudo docker run -it nginxpwner:latest /bin/bash
```


## Usage:

```
Target tab in Burp, select host, right click, copy all URLs in this host, copy to a file

cat urllist | unfurl paths | cut -d"/" -f2-3 | sort -u > /tmp/pathlist 

Or get the list of paths you already discovered in the application in some other way. Note: the paths should not start with /

Finally:

python3 nginxpwner.py https://example.com /tmp/pathlist
```
## Notes:

It actually checks for:

-Gets Ngnix version and gets its possible exploits using searchsploit and tells if it is outdated

-Throws a wordlist specific to Nginx via gobuster

-Checks if it is vulnerable to CRLF via a common misconfiguration of using $uri in redirects

-Checks for CRLF in all of the paths provided

-Checks if the PURGE HTTP method is available from the outside

-Checks for variable leakage misconfiguration

-Checks for path traversal vulnerabilities via merge_slashes set to off

-Tests for differences in the length of responses when using hop-by-hop headers (ex: X-Forwarded-Host)

-Uses Kyubi to test for path traversal vulnerabilities via misconfigured alias

-Tests for 401/403 bypass using X-Accel-Redirect

-Shows the payload to check for Raw backend reading response misconfiguration 

-Checks if the site uses PHP and suggests some nginx-specific tests for PHP sites

-Tests for the common integer overflow vulnerability in Nginx's range filter module (CVE-2017-7529)

The tool uses the Server header in the response to do some of the tests. There are other CMS and so which are built on Nginx like Centminmod, OpenResty, Pantheon or Tengine for example which don't return that header. In that case please use nginx-pwner-no-server-header.py with the same parameters than the other script

Also, for the exploit search to run correctly you should do: searchsploit -u in Kali from time to time

The tool does not check for web cache poisoning/deception vulnerabilities nor request smuggling, you should test that with specific tools for those vulnerabilities. NginxPwner is mainly focused in misconfigurations developers may have introduced in the nginx.conf without being aware of them.

Credit to shibli2700 for his awesome tool Kyubi https://github.com/shibli2700/Kyubi and to all the contributors of gobuster. Credits also to Detectify (which actually discovered many of this misconfigurations in NGINX)
