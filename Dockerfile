FROM python:3.7-stretch


RUN apt-get install git wget 

# installing gobuster 
RUN wget http://ftp.br.debian.org/debian/pool/main/g/gobuster/gobuster_2.0.1-1_amd64.deb &&\
         dpkg -i gobuster_2.0.1-1_amd64.deb && rm gobuster_2.0.1-1_amd64.deb

# kyubi install
RUN git clone https://github.com/shibli2700/Kyubi.git &&\
     cd Kyubi && python3 setup.py install && cd ..


# nginxpwner python dependencies install
COPY requirements.txt .

RUN pip3 install -r requirements.txt

COPY nginxpwner.py nginx-pwner-no-server-header.py ./

