#
# Copyright (C) 2011 ConnId (connid-dev@googlegroups.com)
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

#!/bin/bash
 
set -e
 
info () {
    echo "[INFO] $@"
}
 
info "Running setup"
 
# Check if samba is setup
[ -f /var/lib/samba/.setup ] && info "Already setup..." && exit 0
 
info "Provisioning domain controller..."
 
info "Given admin password: ${SMB_ADMIN_PASSWORD}"
 
rm /etc/samba/smb.conf
 
samba-tool domain provision\
 --server-role=dc\
 --use-rfc2307\
 --dns-backend=SAMBA_INTERNAL\
 --realm=`hostname`\
 --domain=IAM\
 --adminpass=${SMB_ADMIN_PASSWORD}

samba-tool ou create "OU=ARTE,DC=tirasa,DC=net"
samba-tool ou create "OU=1-DGDSIS-Digitalizzazione Sistemi Informativi Statistici,OU=ARTE,DC=tirasa,DC=net"
samba-tool ou create "OU=Utenti,OU=1-DGDSIS-Digitalizzazione Sistemi Informativi Statistici,OU=ARTE,DC=tirasa,DC=net"
samba-tool ou create "OU=NOMENTANA,DC=tirasa,DC=net"
samba-tool ou create "OU=1-DGDSIS-Digitalizzazione Sistemi Informativi Statistici,OU=NOMENTANA,DC=tirasa,DC=net"
samba-tool ou create "OU=Utenti,OU=1-DGDSIS-Digitalizzazione Sistemi Informativi Statistici,OU=NOMENTANA,DC=tirasa,DC=net"
samba-tool ou create "OU=CARACI,DC=tirasa,DC=net"
samba-tool ou create "OU=POLICLINICO,DC=tirasa,DC=net"
samba-tool ou create "OU=PERIFERIA OOPP,DC=tirasa,DC=net"
samba-tool ou create "OU=PERIFERIA UMC,DC=tirasa,DC=net"
samba-tool ou create "OU=SERVIZIO,DC=tirasa,DC=net"
samba-tool ou create "OU=TIROCINANTI,OU=SERVIZIO,DC=tirasa,DC=net"
samba-tool ou create "OU=COMANDATI - DISTACCATI CP,OU=SERVIZIO,DC=tirasa,DC=net"

samba-tool group add GROUP1
samba-tool group add GROUP2
samba-tool group add GROUP3
samba-tool group add GROUP4

## Connection Test
samba-tool user create connection.test Password123 \
 --given-name connection \
 --surname test

## Cristian Capozucco
samba-tool user create capoz P@ssword! \
 --userou "OU=PERIFERIA UMC" \
 --given-name crist \
 --surname capo \
 --initials cc

ldbmodify -H /var/lib/samba/private/sam.ldb.d/DC=TIRASA,DC=NET.ldb capoz.ldif

## Gigi Finizzo
samba-tool user create gfinizzo P@ssword123 \
 --userou "OU=PERIFERIA OOPP" \
 --given-name gigi \
 --surname finizzo

ldbmodify -H /var/lib/samba/private/sam.ldb.d/DC=TIRASA,DC=NET.ldb gigi.ldif

## Fabio Martelli
samba-tool user create fmartelli Password123 \
 --userou "OU=TIROCINANTI,OU=SERVIZIO" \
 --given-name fabio \
 --surname martelli

ldbmodify -H /var/lib/samba/private/sam.ldb.d/DC=TIRASA,DC=NET.ldb fabio.ldif

## Test sincronizzazione 1
samba-tool user create test.1 Password123 \
 --userou "OU=POLICLINICO" \
 --given-name test \
 --surname uno

## Test sincronizzazione 2
samba-tool user create test.2 Password123 \
 --userou "OU=CARACI" \
 --given-name test \
 --surname due

## Test sincronizzazione 3
samba-tool user create test.3 Password123 \
 --userou "OU=COMANDATI - DISTACCATI CP,OU=SERVIZIO" \
 --given-name test \
 --surname tre


samba-tool group addmembers GROUP1 capoz,gfinizzo
samba-tool group addmembers GROUP2 capoz,gfinizzo
samba-tool group addmembers GROUP3 fmartelli

mv /etc/samba/smb.conf /var/lib/samba/private/smb.conf
 
touch /var/lib/samba/.setup

cp -r tls/* /var/lib/samba/private/tls/.
chown -R 0 /var/lib/samba/private/tls

