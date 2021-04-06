# Nginxpwner

<p align="center"><img src="https://i.postimg.cc/vm3LWFj4/nginxpwner.png" /></p>

Nginxpwner is a simple tool to look for common Nginx misconfigurations and vulnerabilities.

## Install:

```
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

Credit to shibli2700 for his awesome tool Kyubi https://github.com/shibli2700/Kyubi
