# nginxpwner

Install:

git clone https://github.com/stark0de/nginxpwner
cd nginxpwner
chmod +x install.sh
./install.sh


Usage:

Target tab in Burp, select host, right click, copy all URLs in this host, copy to a file
cat urllist | unfurl paths | cut -d"/" -f2-10 > /tmp/pathlist

python3 nginxpwner.py https://example.com /tmp/pathlist
