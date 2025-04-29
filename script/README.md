This script is developed to transform PCAP files into CSV

To properly run this script it needs to be initated from a Unix terminal using the ./captocsv.py \<input pcap file> \<output csv file>

Python3 needs to be installed, along with the pyhton libraries dpkt, socket, csv, sys, geoip2, and datetime.

Additonally the geoip data base provided by MaxMind (https://dev.maxmind.com/geoip/geolite2-free-geolocation-data/) need to be located in the same folder as the script.
