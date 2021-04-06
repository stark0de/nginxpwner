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

## Usage:

```
Target tab in Burp, select host, right click, copy all URLs in this host, copy to a file

cat urllist | unfurl paths | cut -d"/" -f2-3 | sort -u > /tmp/pathlist 

Or get the list of paths you already discovered in the application in some other way. Note: the paths should not start with /

Finally:

python3 nginxpwner.py https://example.com /tmp/pathlist
```
## Notes:

The tool uses the Server header in the response to do some of the tests. There are other CMS and so which are built on Nginx like Centminmod, OpenResty, Pantheon or Tengine for example which don't return that header. In that case please use nginx-pwner-no-server-header.py with the same parameters than the other script


Credit to shibli2700 for his awesome tool Kyubi https://github.com/shibli2700/Kyubi
