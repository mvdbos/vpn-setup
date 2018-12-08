#!/bin/bash -e

# firewall
# https://www.strongswan.org/docs/LinuxKongress2009-strongswan.pdf
# https://wiki.strongswan.org/projects/strongswan/wiki/ForwardingAndSplitTunneling
# https://www.zeitgeist.se/2013/11/26/mtu-woes-in-ipsec-tunnels-how-to-fix/
set -x

# Config
USEDHCP="true"
#VPNDNS="8.8.8.8,8.8.4.4"
VPNDNS="192.168.2.251"

[[ $(id -u) -eq 0 ]] || exit_badly "Please re-run as root (e.g. sudo ./path/to/this/script)"

# Install required packages
export DEBIAN_FRONTEND=noninteractive
#apt-get -o Acquire::ForceIPv4=true update
#apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
#apt autoremove -y
#apt-get -o Acquire::ForceIPv4=true install -y strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins moreutils iptables-persistent

# Network interface used
ETH0ORSIMILAR=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
# Internal IP
IP=$(ifdata -pa $ETH0ORSIMILAR)
# External IP
VPNHOST=$(dig +short myip.opendns.com @resolver1.opendns.com)


# A pre set IP pool for VPN clients or use DHCP if you have the dhcp plugin for StrongSwan
VPNIPPOOL="10.10.0.0/16"
RIGHTSOURCEIP=$VPNIPPOOL

if [[ $USEDHCP = "true" ]]
then
	VPNIPPOOL=$(ip route | grep proto | awk -- '{ print $1 }')
	RIGHTSOURCEIP="%dhcp"
fi

# set the firewall
iptables -P INPUT   ACCEPT
iptables -P FORWARD ACCEPT
iptables -P OUTPUT  ACCEPT

iptables -F
iptables -t nat -F
iptables -t mangle -F

# INPUT

# accept anything already accepted
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT

# accept anything on the loopback interface
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# drop invalid packets
iptables -A INPUT -m state --state INVALID -j DROP

# rate-limit repeated new requests from same IP to any ports
#iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --set
#iptables -I INPUT -i $ETH0ORSIMILAR -m state --state NEW -m recent --update --seconds 300 --hitcount 60 -j DROP

# allow SSH from our subnet
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT

# Allow the DNS resolver for PI-hole and the web interface
iptables -A INPUT -p tcp --destination-port 53 -j ACCEPT
iptables -A INPUT -p udp --destination-port 53 -j ACCEPT
iptables -A INPUT -p tcp --destination-port 80 -j ACCEPT


# VPN

# accept IPSec/NAT-T for VPN (ESP not needed with forceencaps, as ESP goes inside UDP)
iptables -A INPUT -p udp --dport  500 -j ACCEPT
iptables -A INPUT -p udp --dport 4500 -j ACCEPT

# forward VPN traffic anywhere
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $VPNIPPOOL -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $VPNIPPOOL -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $VPNIPPOOL -o $ETH0ORSIMILAR -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $VPNIPPOOL -o $ETH0ORSIMILAR -j MASQUERADE


# fall through to drop any other input and forward traffic

iptables -A INPUT   -j DROP
iptables -A FORWARD -j DROP

iptables -L

debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v4 boolean true"
debconf-set-selections <<< "iptables-persistent iptables-persistent/autosave_v6 boolean true"
dpkg-reconfigure iptables-persistent


# ip_forward is for VPN
# ip_no_pmtu_disc is for UDP fragmentation
# others are for security
# Check if we have already set config, else set
grep -Fq 'IKEv2-setup' /etc/sysctl.conf || echo '
# https://github.com/jawj/IKEv2-setup
net.ipv4.ip_forward = 1
net.ipv4.ip_no_pmtu_disc = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
' >> /etc/sysctl.conf

sysctl -p


# Set Strongswan config
# these ike and esp settings are tested on Mac 10.14, iOS 12 and Windows 10
# iOS and Mac with appropriate configuration profiles use AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_521 
# Windows 10 uses AES_GCM_16_256/PRF_HMAC_SHA2_384/ECP_384
echo "config setup
  strictcrlpolicy=yes
  uniqueids=never

conn roadwarrior
  auto=add
  compress=no
  type=tunnel
  keyexchange=ikev1
  fragmentation=yes
  forceencaps=yes
  dpdaction=clear
  dpddelay=900s
  rekey=no
  left=%any
  leftid=${VPNHOST}
  leftsubnet=0.0.0.0/0
  leftauth=psk
  right=%any
  rightid=%any
  rightdns=${VPNDNS}
  rightsourceip=${VPNIPPOOL}
  rightauth=psk
  rightauth2=xauth
" > /etc/ipsec.conf

## TODO: set ipsec.secrets idempotently

ipsec restart
