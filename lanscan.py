#!/usr/bin/python3
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
from tabulate import tabulate

class scan:
  def Arp(self, ip):
    self.ip = ip
    print(ip)
    arp_r = scapy.ARP(pdst=ip)
    br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    request = br/arp_r
    answered, unanswered = scapy.srp(request, timeout=1)
    
    hosts = []

    for i in answered:
      ip, mac = i[1].psrc, i[1].hwsrc
      try:
        vendor = MacLookup().lookup(mac)
      except Exception as e:
        vendor = 'Unknown'
      hosts.append([ip, mac, vendor])
      #print(ip, '\t' + mac, '\t' + vendor)

    print()
    print(tabulate(hosts, headers=['IP', 'MAC', 'Vendor'], tablefmt='orgtbl'))

arp = scan()
arp.Arp('192.168.1.1/24')