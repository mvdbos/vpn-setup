#!/bin/bash -e

function error {
  echo $1
  exit 1
}

[[ $(id -u) -eq 0 ]] || error "Please run as root"

# Install required packages
export DEBIAN_FRONTEND=noninteractive
apt-get -o Acquire::ForceIPv4=true update
apt-get -o Acquire::ForceIPv4=true --with-new-pkgs upgrade -y
apt autoremove -y
apt-get -o Acquire::ForceIPv4=true install -y strongswan libstrongswan-standard-plugins strongswan-libcharon libcharon-extra-plugins moreutils iptables-persistent

NET_INTERFACE=$(ip route get 8.8.8.8 | awk -- '{printf $5}')
EXTERNAL_IP=$(dig +short myip.opendns.com @resolver1.opendns.com)
SUBNET=$(ip route | grep proto | awk -- '{ print $1 }')
LOCAL_DNS=$(dhcpcd -T | grep domain_name_servers | cut -d"=" -f2 | sed -e "s/'//g")

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

# allow SSH
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
iptables -A FORWARD --match policy --pol ipsec --dir in  --proto esp -s $SUBNET -j ACCEPT
iptables -A FORWARD --match policy --pol ipsec --dir out --proto esp -d $SUBNET -j ACCEPT

# reduce MTU/MSS values for dumb VPN clients
iptables -t mangle -A FORWARD --match policy --pol ipsec --dir in -s $SUBNET -o $NET_INTERFACE -p tcp -m tcp --tcp-flags SYN,RST SYN -m tcpmss --mss 1361:1536 -j TCPMSS --set-mss 1360

# masquerade VPN traffic over eth0 etc.
iptables -t nat -A POSTROUTING -s $SUBNET -o $NET_INTERFACE -m policy --pol ipsec --dir out -j ACCEPT  # exempt IPsec traffic from masquerading
iptables -t nat -A POSTROUTING -s $SUBNET -o $NET_INTERFACE -j MASQUERADE


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
  leftid=${EXTERNAL_IP}
  leftsubnet=0.0.0.0/0
  leftauth=psk
  right=%any
  rightid=%any
  rightdns=${LOCAL_DNS}
  rightsourceip=%dhcp
  rightauth=psk
  rightauth2=xauth
" > /etc/ipsec.conf

## TODO: set ipsec.secrets idempotently

ipsec restart
