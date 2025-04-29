#!/usr/bin/env python3

#----------------------------------------------------------------#
# Prints converts high level info from pcap to CSV
# (c) 2020 Barry Irwin
# Edits of script conducted by
# (c) 2024 Eddie Kallander 
#
#----------------------------------------------------------------#

import dpkt
import socket
import csv
import sys
import geoip2.database
from datetime import datetime, timezone, timedelta

# Path to GeoLite2 database
geoip_db_path = 'GeoLite2-City.mmdb'

#Argument check
if len(sys.argv) < 3:
    print(sys.argv[0] , 'Must provide and input pcap file and an output csv file')
    sys.exit(-1)

infile=sys.argv[1]
outfile=sys.argv[2]



#open file
f = open(infile, 'rb')

#initialize readers
pcap = dpkt.pcap.Reader(f)
georeader = geoip2.database.Reader(geoip_db_path)


#itereate thru file

with open(outfile, mode='w') as pcap_file:
    pcap_writer = csv.writer(pcap_file, delimiter=',', quotechar='"', quoting=csv.QUOTE_MINIMAL)

    #Header
    pcap_writer.writerow([
        "Timestamp", "Source IP", "Source Country", "Source City",
        "Destination IP", "TTL", "IP Length", "Protocol", "Source Port", "Destination Port"  
    ])

    #for loop iteraties thru timestime and binary data(packet structure)
    for ts, buf in pcap:
        
        #empty packet list
        packet = []
        #decoding eth frame
        eth = dpkt.ethernet.Ethernet(buf)
        #IP layer extraction
        ip = eth.data
        
        #fields to convert
        ptime=str(datetime.fromtimestamp(ts, timezone(timedelta(hours=2))))
        srcip = socket.inet_ntoa(ip.src)
        try:
            src_city = georeader.city(srcip)
            src_city_name = src_city.city.name
            src_country = src_city.country.name
        except Exception:
            src_city_name = "Unknown"
            src_country = "Unknown"
        destip = socket.inet_ntoa(ip.dst)
        ttl = ip.ttl
        protocol = ip.p
        
        #append to list
        packet.append(ptime)
        packet.append(srcip)
        packet.append(src_country)
        packet.append(src_city_name)
        packet.append(destip)
        packet.append(ttl)
        packet.append(ip.len)
        packet.append(ip.p)
        
        #Default port values
        #src_port = -1
        #dest_port = -1
        
        #Extract port number for TCP and UDP

        if protocol == 6:  # TCP
            tcp = ip.data
            try:
                sport = tcp.sport
                dport = tcp.dport
            except:
                sport=-1
                dport=-1
            packet.append(sport)
            packet.append(dport)
        elif protocol == 17:  # UDP
            udp = ip.data
            try:
                src_port = udp.sport
                dest_port = udp.dport
            except:
                sport=-1
                dport=-1
            packet.append(sport)
            packet.append(dport)
        elif protocol == 1:
            icmp = ip.data
            try:
                t=icmp.type
                c=icmp.code
            except:
                t=-1
                c=-1
            packet.append(t)
            packet.append(c)
        else:
            proto=ip.data
            packet.append(sport)
            packet.append(dport)

        
        pcap_writer.writerow(packet)

        del ip
        src_port=-1
        dest_port=-1
        ttl=-1
        del ptime
