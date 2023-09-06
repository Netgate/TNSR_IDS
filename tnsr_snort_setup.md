# TNSR IDS Setup using ERSPAN

### Test Layout:

| Role | IP Address | Interface |
|--|--|--|
| Traffic source VM | 203.0.113.10/24 | ens224 |
| TNSR WAN | 203.0.113.2/24 | GigabitEthernet13/0/0 |
| TNSR LAN | 192.0.2.1/24 | GigabitEthernet1b/0/0 |
| IDS/Target VM | 192.0.2.5/24 | ens256 |

### GRE/ERSPAN Layout:

| GRE Role | Value |
|--|--|
| GRE/ERSPAN Source | 192.0.2.1 |
| GRE/ERSPAN Receiver | 192.0.2.5 |
| Interface spanned to GRE | GigabitEthernet13/0/0 |

## TNSR Setup

Add the ACL which will be filled by `tnsrids`, it needs a permit rule that
will always come last:

    configure
    acl snortblock
    rule 2147483646
    action permit
    ip-version ipv4
    exit
    exit

Configure the external interface, and add the ACL from above:

    interface GigabitEthernet13/0/0
    ip address 203.0.113.2/24
    description External/WAN
    access-list input acl snortblock sequence 10
    enable
    exit

Configure the internal interface:

    interface GigabitEthernet1b/0/0
    ip address 192.0.2.1/24
    description Internal/LAN
    enable
    exit

Configure the GRE/ERSPAN interface and corresponding SPAN:

    gre gre1
    dest 192.0.2.5
    source 192.0.2.1
    tunnel-type erspan session-id 1
    instance 1
    exit
    int gre1
    enable
    exit
    span GigabitEthernet13/0/0
    onto gre1 hw both
    exit

Enable the RESTCONF server:

    restconf
    enable true
    global authentication-type client-certificate
    global server-certificate SRV
    global server-key SRV
    global server-ca-cert-path TNSR
    server dataplane 192.0.2.1 443 true

**WARNING**: You are able to use previously created certificate or to create it through the TNSR

## Setup tnsrids Daemon

See [README.md](README.md)

## IDS Receiver Setup

Setup the network interface used between the IDS Receiver and TNSR

    $ sudo vi /etc/sysconfig/network-scripts/ifcfg-ens256
    TYPE=Ethernet
    PROXY_METHOD=none
    BROWSER_ONLY=no
    BOOTPROTO=none
    DEFROUTE=yes
    IPV4_FAILURE_FATAL=no
    IPV6INIT=yes
    IPV6_AUTOCONF=yes
    IPV6_DEFROUTE=yes
    IPV6_FAILURE_FATAL=no
    IPV6_ADDR_GEN_MODE=stable-privacy
    NAME=ens256
    UUID=b2953c4e-5fac-411b-b357-6dd50260062f
    DEVICE=ens256
    ONBOOT=yes
    IPADDR=192.0.2.5
    PREFIX=24
    #GATEWAY=192.0.2.1
    DNS1=192.0.2.1
    DOMAIN="example.com"
    IPV6_PRIVACY=no

This route is added for testing to/from hosts on the TNSR WAN side:

    $ sudo vi /etc/sysconfig/network-scripts/route-ens256
    203.0.113.0/24 via 192.0.2.1 dev ens256

Use this command to temporarily add a the route instead of making it permanent:

    $ sudo route add -net 203.0.113.0/24 gw 192.0.2.1

Traffic arriving on this system will need to be passed through the host firewall
which is likely `firewalld` if this is a CentOS system. Alternately, disable
`firewalld` since this system should be isolated on the network and only receiving traffic:

    $ sudo systemctl stop firewalld
    $ sudo systemctl disable firewalld

Restart the network and pick up the new interface configuration::

    $ sudo systemctl restart network

This next step is likely optional. There is no need to process or handle the
received traffic on an interface in this way, it only needs to arrive at the
interface snort is bound to, it can decode the GRE directly.

    $ sudo modprobe ip_gre
    sudo vi /etc/sysconfig/network-scripts/ifcfg-tun0
    DEVICE=tun0
    BOOTPROTO=none
    ONBOOT=yes
    TYPE=GRE
    #PEER_INNER_IPADDR=198.18.0.1
    PEER_OUTER_IPADDR=192.0.2.1
    #MY_INNER_IPADDR=198.18.0.2
    MY_OUTER_IPADDR=192.0.2.5

    $ sudo ifup tun0

Setup snort, for example on CentOS by following
https://upcloud.com/resources/tutorials/installing-snort-on-centos

Snort **DOES NOT** need to run on the GRE interface/tun, only on the interface with the address used to receive the GRE/ERSPAN traffic. Snort will see and decapsulate the GRE traffic internally.

Snort `HOME_NET` should include addresses from TNSR to alert on:

    ipvar HOME_NET [192.0.2.0/24,203.0.113.2/32]

In the `snort` configuration, use `alert_syslog` output:

    output alert_syslog: LOG_LOCAL5 LOG_ALERT

Run snort:

    $ sudo snort -i ens256 -u snort -g snort -c /etc/snort/snort.conf

Configure `rsyslog` to transport messages to the host where `tnsrids` is running::

    $ sudo vi /etc/rsyslog.conf
    local5.* @172.27.10.36:12345

Restart rsyslog:

    $ sudo systemctl restart rsyslog

A rule to flag any ICMP traffic is a good test to generate alerts quickly.

    $ sudo vi /etc/snort/rules/local.rules
    alert icmp !$HOME_NET any -> $HOME_NET any (msg:"ICMP test"; sid:10000001; rev:001;

## Traffic Generator Setup (Testing)

    $ sudo vi /etc/sysconfig/network-scripts/ifcfg-ens224
    TYPE=Ethernet
    PROXY_METHOD=none
    BROWSER_ONLY=no
    BOOTPROTO=none
    DEFROUTE=yes
    IPV4_FAILURE_FATAL=no
    IPV6INIT=yes
    IPV6_AUTOCONF=yes
    IPV6_DEFROUTE=yes
    IPV6_FAILURE_FATAL=no
    IPV6_ADDR_GEN_MODE=stable-privacy
    NAME=ens224
    UUID=5a2a73ce-3c7b-4cf0-b32c-309c50247b77
    DEVICE=ens224
    ONBOOT=yes
    IPADDR=203.0.113.10
    PREFIX=24
    #GATEWAY=172.27.44.1
    #DNS1=172.27.32.5
    #DNS2=172.27.32.6
    DOMAIN="example.com"
    IPV6_PRIVACY=no

Add a route similar to the IDS box, to reach the other side:

    $ sudo vi /etc/sysconfig/network-scripts/route-ens224
    192.0.2.0/24 via 203.0.113.2 dev ens224

Or temporarily add the route:

    $ sudo route add -net 192.0.2.0/24 gw 203.0.113.2

Restart the network services to pick up new interface settings::

    $ sudo systemctl restart network

When testing, use `ping` or `hping` to source traffic from other addresses, to see if alerts trigger ACL entries as expected:

    $ ping -I ens224 203.0.113.2
    $ sudo hping 203.0.113.2 -I ens224 --icmp --spoof 203.0.113.66
    $ nc -vz -s 203.0.113.10 203.0.113.2 22

Install `hping` from FreeBSD packages/ports or using your distribution's package manager (on CentOS it is `hping3`, available with `epel-release`).
Similarly, `nmap` and its included utility `nc` are useful for generating traffic that can tickle snort to alert.

CentOS 7:

    $ sudo yum install epel-release
    $ sudo yum install hping3 nmap

## Resources

IDS configuration used during testing: [snort.conf](snort.conf)
