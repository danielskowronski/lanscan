#!/usr/bin/python3
import scapy.all as scapy
from mac_vendor_lookup import MacLookup
from tabulate import tabulate
import csv
import socket
import struct
from netaddr import IPNetwork
from multiprocessing import Pool

def ip2int(addr):
  return struct.unpack("!I", socket.inet_aton(addr))[0]
def sortHostsByIP(hosts):
  return {k: v for k, v in sorted(hosts.items(), key=lambda item: ip2int(item[1].ip))}

class host:
  ip=''
  mac='ff:ff:ff:ff:ff:ff'
  desc=''
  vendor=''
  
  def __init__(self,ip,mac,desc,vendor):
    self.ip=ip
    self.mac=mac
    self.desc=desc
    self.vendor=vendor
  def __repr__(self):
    return self.mac+'=='+self.ip

class bcolors:
  HEADER = '\033[95m'
  OKBLUE = '\033[94m'
  OKGREEN = '\033[92m'
  WARNING = '\033[93m'
  FAIL = '\033[91m'
  ENDC = '\033[0m'
  BOLD = '\033[1m'
  UNDERLINE = '\033[4m'

class config:
  subnet='127.0.0.1/8'
  macdefs=[]
  def ReadConfigFile(self, path):
    with open(path, newline='') as csvfile:
      configreader = csv.reader(csvfile, delimiter=',', quotechar='\'')
      for line in configreader:
        if len(line)!=2:
          continue

        if line[0]=='subnet':
          self.subnet=line[1]
        else:
          self.macdefs.append([line[0], line[1]])
  def CheckDescription(self, mac):
    for macdef in self.macdefs:
      if mac.lower() == macdef[0].lower():
        return f"{bcolors.OKGREEN}{macdef[1]}{bcolors.ENDC}"
    return f"{bcolors.WARNING}UNKNOWN{bcolors.ENDC}"

class scan:
  def ArpScan(self, ipobj):
    hosts=dict()
    ip = str(ipobj)
    print(ip+' ', end = '', flush=True)
    arp_r = scapy.ARP(pdst=ip)
    br = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    request = br/arp_r
    
    retries = []
    for i in range(0,3):
      answered, unanswered = scapy.srp(request, timeout=2, verbose=False)
      retries.append(answered)

    for t in retries:
      for i in t:
        ip, mac = i[1].psrc, i[1].hwsrc
        try:
          vendor = MacLookup().lookup(mac)
        except Exception as e:
          vendor = 'Unknown'
        desc=cfg.CheckDescription(mac)
        hosts[mac]=host(ip, mac, desc, vendor)
    return hosts

  def PrintReport(self, result):
    hoststab=[]
    hosts=sortHostsByIP(result)
    for hostobj in hosts.values():
      hoststab.append([hostobj.ip, hostobj.mac, hostobj.desc, hostobj.vendor])

    print()
    print(tabulate(hoststab, headers=['IP', 'MAC', 'Description', 'Vendor'], tablefmt='orgtbl'))

if __name__ == '__main__':
  cfg = config()
  cfg.ReadConfigFile('./config.csv')
  arp = scan()
  ## arp.ArpScan(cfg.subnet) ## this won't poll stuff like iPhones that are sleeping on WiFi
  with Pool(processes=256) as pool:
    result = pool.map(arp.ArpScan, IPNetwork(cfg.subnet), 2)
  hosts=dict()
  for r in result:
    hosts.update(r)
  arp.PrintReport(hosts)
