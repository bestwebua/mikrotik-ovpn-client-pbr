# mikrotik-ovpn-client-pbr
<h1>CentOS OpenVPN Server + Mikrotik OVPN client + Policy Based Routing guide.</h1>
<h2>Step 1. CentOS OpenVPN Server installation.</h2>
You already have server with installed CentOS 6.5. Let's install OpenVPN!

```bash
wget http://dl.fedoraproject.org/pub/epel/6/i386/epel-release-6-8.noarch.rpm
rpm -Uvh epel-release-6-8.noarch.rpm
yum install openvpn easy-rsa
```
This method activates TLS/SSL encryption on the server, let's find our easy-rsa (/usr/share/easy-rsa):
```bash
cd /etc/openvpn
mkdir easy-rsa
cp -R /usr/share/easy-rsa/2.0/* easy-rsa/
chmod -R +x easy-rsa/
```
Initializing the script:
```bash
cd easy-rsa/
source ./vars
./clean-all
```
Create a CA certificate and key:
```bash
./build-ca
```
Create a certificate/key for the server:
```bash
./build-key-server server
```
Generating keys for encryption of SSL/TLS connections:
```bash
./build-dh
```
And create the keys for yourself:
```bash
./build-key client
```
Create and tune your openvpn.config:
```bash
cp /usr/share/doc/openvpn-2.3.2/sample/sample-config-files/server.conf /etc/openvpn
```
Edit your /etc/openvpn/server.conf:
```bash
local xxx.xxx.xxx.xxx #external ip of our vpn-server
port 1194
proto tcp
dev tun

ca  /etc/openvpn/easy-rsa/keys/ca.crt
cert    /etc/openvpn/easy-rsa/keys/server.crt
key     /etc/openvpn/easy-rsa/keys/server.key
dh  /etc/openvpn/easy-rsa/keys/dh2048.pem

server 10.0.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120

user nobody
group nobody
persist-key
persist-tun
status /var/log/openvpn-status.log
log /var/log/openvpn.log
verb 3
```
Now you can start the OpenVPN service:
```bash
service openvpn start
```
Add openvpn service in autoload:
```bash
chkconfig openvpn on
```
Check if the device for the tunnel has appeared:
```bash
ifconfig tun0
```
Is assigned address and port for OpenVPN server?:
```bash
netstat -tupln
```
Edit the file /etc/sysctl.conf:
```bash
net.ipv4.ip_forward = 1
```
Loading kernel variables from updated sysctl.conf:
```bash
sysctl -p
```
Add rules into iptables /etc/sysconfig/iptables:
```bash
*nat
:PREROUTING ACCEPT [0:0]
:POSTROUTING ACCEPT [1:124]
:OUTPUT ACCEPT [1:124]
-A POSTROUTING -s 10.0.0.0/24 -o eth0 -j MASQUERADE #openvpn
COMMIT
*filter
:INPUT ACCEPT [126:10528]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [112:13370]
-A INPUT -i tun0 -j ACCEPT #openvpn
-A INPUT -p tcp -m tcp --dport 1194 -j ACCEPT #openvpn
COMMIT
```
Restart the service:
```bash
service iptables restart
```
That's all. Your OpenVPN server is ready! :)

<h2>Step 2. Mikrotik router as OpenVPN Client.</h2>
<h3>Mikrotik OVPN client installation.</h3>
<h4>Please, keep in mind:</h4>
<ul>
<li>UDP is not supported</li>
<li>LZO compression is not supported</li>
<li>username/passwords are not mandatory</li>
</ul>
Let's go:
```bash
ssh admin@192.168.1.1
```
```bash
  MMMM    MMMM       KKK                          TTTTTTTTTTT      KKK
  MMM MMMM MMM  III  KKK  KKK  RRRRRR     OOOOOO      TTT     III  KKK  KKK
  MMM  MM  MMM  III  KKKKK     RRR  RRR  OOO  OOO     TTT     III  KKKKK
  MMM      MMM  III  KKK KKK   RRRRRR    OOO  OOO     TTT     III  KKK KKK
  MMM      MMM  III  KKK  KKK  RRR  RRR   OOOOOO      TTT     III  KKK  KKK

  MikroTik RouterOS 6.39.1 (c) 1999-2017       http://www.mikrotik.com/

[?]             Gives the list of available commands
command [?]     Gives help on the command and list of arguments

[Tab]           Completes the command/word. If the input is ambiguous,
                a second [Tab] gives possible options

/               Move up to base level
..              Move up one level
/command        Use command at the base level
```
<h4>Check your Mikrotik OS version</h4>
All the code in this repo is for version 6.39.1. If yours is older than that go ahead and upgrade it first.
```bash
system package update download
```
<h4>Import OpenVPN certificates</h4>
You'll need some files from your OpenVPN server or VPN provider, only 2 files are required: client.crt  client.key. Upload and import these certificates to your Mikrotik.
```bash
scp client.crt admin@192.168.1.1:/
scp client.key admin@192.168.1.1:/
certificate import file-name=client.crt
certificate import file-name=client.key
```
You can check that it's worked:
```bash
certificate print
```
```bash
Flags: K - private-key, D - dsa, L - crl, C - smart-card-key, A - authority, I - issued, R - revoked, E - expired, T - trusted 
 #          NAME               COMMON-NAME        SUBJECT-ALT-NAME      FINGERPRINT              
 0 K      T client.crt_0       OpenVPN                                  12911f9e101be5b3e15cd...
```
<h4>Create an OpenVPN PPP profile</h4>
This section contains all the details of how you will connect to the server, the following worked for me.
```bash
ppp profile add name=OVPN-client change-tcp-mss=yes only-one=yes use-encryption=yes use-mpls=no use-compression=no
```
You can check that it's worked:
```bash
ppp profile print
```
```bash
Flags: * - default 
 0 * name="default" use-mpls=default use-compression=default use-encryption=default only-one=default change-tcp-mss=yes use-upnp=default 
     address-list="" on-up="" on-down="" 
 1   name="OVPN-client" use-mpls=no use-compression=no use-encryption=yes only-one=yes change-tcp-mss=yes use-upnp=default address-list="" 
     on-up="" on-down="" 
 2 * name="default-encryption" use-mpls=default use-compression=default use-encryption=yes only-one=default change-tcp-mss=yes 
     use-upnp=default address-list="" on-up="" on-down=""
```
<h4>Create an OpenVPN interface</h4>
Here we actually create an interface for the VPN connection. Important! Change xxx.xxx.xxx.xxx to your own server address (ip address or domain name). User/password properties seem to be mandatory on the client even if the server doesn't have auth-user-pass-verify enabled.
```bash
interface ovpn-client add name=ovpn-client connect-to=xxx.xxx.xxx.xxx port=1194 mode=ip user="openvpn" password="" profile=OVPN-client certificate=client.crt_0 auth=sha1 cipher=blowfish128 add-default-route=yes
```
Check out your new open-vpn connection:
```bash
interface ovpn-client print
```
```bash
Flags: X - disabled, R - running 
 0  R name="ovpn-client" mac-address=xx:xx:xx:xx:xx:xx max-mtu=1500 connect-to=xxx.xxx.xxx.xxx port=1194 mode=ip user="openvpn" password="" profile=OVPN-client certificate=client.crt_0 auth=sha1 cipher=blowfish128 add-default-route=yes
```
```bash
interface ovpn-client monitor 0
```
```bash
  status: connected
  uptime: 18h38m31s
  encoding: BF-128-CBC/SHA1
  mtu: 1500
```
<h4>Configure the firewall</h4>
```bash
ip firewall filter print
```
```bash
Flags: X - disabled, I - invalid, D - dynamic 
 0  D ;;; special dummy rule to show fasttrack counters
      chain=forward action=passthrough 
 1    ;;; fasttrack
      chain=forward action=fasttrack-connection connection-state=established,related log=no log-prefix="" 
 2    ;;; accept established,related
      chain=forward action=accept connection-state=established,related log=no log-prefix="" 
 3    ;;; drop invalid
      chain=forward action=drop connection-state=invalid log=no log-prefix="" 
 4    ;;; drop all from WAN not DSTNATed
      chain=forward action=drop connection-state=new connection-nat-state=!dstnat in-interface=ether1 log=no log-prefix="" 
 5    chain=input action=accept protocol=icmp log=no log-prefix="" 
 6    chain=input action=accept connection-state=established log=no log-prefix="" 
 7    chain=input action=accept connection-state=related log=no log-prefix="" 
 8    chain=input action=drop in-interface=pppoe-out1 log=no log-prefix="" 
```
<h4>Configure masquerade</h4>
We add new masquerade NAT rule:
```bash
ip firewall nat add chain=srcnat action=masquerade out-interface=ovpn-client log=no log-prefix=""
```
Check out it:
```bash
ip firewall nat print
```
<h4>Configuring Policy Based Routing</h4>
Here we add some resources that we wanna using through our OpenVPN client. We can use domains or ip's in address:
```bash
ip firewall address-list add list="OpenVPN" address="somehost.com"
ip firewall address-list add list="OpenVPN" address="xxx.xxx.xxx.xxx"
ip firewall address-list add list="OpenVPN" address="xxx.xxx.xxx.xxx/xx"
```
<h4>Configuring mangle</h4>
Then we set up mangle rule which marks packets coming from the local network and destined for the internet with a mark named 'vpn_traffic':
```bash
ip firewall mangle add chain=prerouting action=mark-routing new-routing-mark=vpn_traffic passthrough=yes dst-address-list=OpenVPN log=no
```
Check out it:
```bash
ip firewall mangle print
```
```bash
Flags: X - disabled, I - invalid, D - dynamic
 0  D ;;; special dummy rule to show fasttrack counters
      chain=prerouting action=passthrough
 1  D ;;; special dummy rule to show fasttrack counters
      chain=forward action=passthrough
 2  D ;;; special dummy rule to show fasttrack counters
      chain=postrouting action=passthrough
 3    chain=prerouting action=mark-routing new-routing-mark=vpn_traffic passthrough=yes dst-address-list=OpenVPN log=no log-prefix=""
```
<h4>Configure routing</h4>
Next we tell the router that all traffic with the 'vpn_traffic' mark should go through the VPN interface:
```bash
ip route add gateway="ovpn-client" type="unicast" routing-mark="vpn_traffic"
```
Check out it:
```bash
ip route print
```
```bash
Flags: X - disabled, A - active, D - dynamic, C - connect, S - static, r - rip, b - bgp, o - ospf, m - mme, 
B - blackhole, U - unreachable, P - prohibit 
 #      DST-ADDRESS        PREF-SRC        GATEWAY            DISTANCE
 0 A S  0.0.0.0/0                          ovpn-client               1
 1 ADS  0.0.0.0/0                          10.10.1.4                 0
 2  DS  0.0.0.0/0                          10.0.0.1                  1
 3 ADC  10.0.0.1/32        10.0.0.6        ovpn-client               0
 4 ADC  10.10.1.4/32       10.10.16.25     pppoe-out1                0
 5 ADS  xxx.xxx.xxx.xxx/xx                 10.10.1.4                 0
 6 ADC  192.168.1.0/24     192.168.1.1     bridge                    0
```
Please note, if you not see ADS route with your OpenVPN server ip you have forgotten add-default-route=yes in your ovpn-client.
That's all! Your Mikrotik Policy Based Routing should now be routed through the your OpenVPN server.
