#!/bin/sh
set -e

HOST_TYPE=${HOST_TYPE:-workstation}

# Configure Samba based on host type
case "$HOST_TYPE" in
  dc)
    sed -i 's/netbios name = WIN-SRV/netbios name = WIN-DC01/' /etc/samba/smb.conf
    sed -i 's/server string = Windows Server/server string = Windows Server 2019 (Domain Controller)/' /etc/samba/smb.conf
    ;;
  workstation)
    sed -i 's/server string = Windows Server/server string = Windows 10 Pro/' /etc/samba/smb.conf
    ;;
  laptop)
    sed -i 's/server string = Windows Server/server string = Windows 11 Home/' /etc/samba/smb.conf
    ;;
esac

# Create Samba user
(echo "Passw0rd!"; echo "Passw0rd!") | smbpasswd -a -s nobody 2>/dev/null || true

# Start Samba
smbd --foreground --no-process-group &
nmbd --foreground --no-process-group &

# Simulate extra Windows ports with socat
# RPC Endpoint Mapper (135)
socat TCP4-LISTEN:135,fork,reuseaddr EXEC:'printf "MSRPC"' &

# RDP (3389)
socat TCP4-LISTEN:3389,fork,reuseaddr EXEC:'printf "\x03\x00\x00\x13\x0e\xd0\x00\x00\x124\x00\x02\x00\x08\x00\x02\x00\x00\x00"' &

# Kerberos (88) — DC only
if [ "$HOST_TYPE" = "dc" ]; then
  socat TCP4-LISTEN:88,fork,reuseaddr EXEC:'printf "KRB5"' &
  socat UDP4-LISTEN:88,fork,reuseaddr EXEC:'printf "KRB5"' &
  # LDAP (389)
  socat TCP4-LISTEN:389,fork,reuseaddr EXEC:'printf "0\x0c\x02\x01\x01a\x07\x0a\x01\x00\x04\x00\x04\x00"' &
  # LDAPS (636)
  socat TCP4-LISTEN:636,fork,reuseaddr EXEC:'printf "LDAPS"' &
  # Global Catalog (3268, 3269)
  socat TCP4-LISTEN:3268,fork,reuseaddr EXEC:'printf "LDAP-GC"' &
  socat TCP4-LISTEN:3269,fork,reuseaddr EXEC:'printf "LDAPS-GC"' &
fi

echo "[$HOST_TYPE] Services started — SMB:139/445, RDP:3389, RPC:135"
wait
