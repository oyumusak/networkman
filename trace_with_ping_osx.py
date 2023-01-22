#!/usr/local/bin/python3
# -*- coding: utf-8 -*-
#  -*- cerebnismus -*-

# Implementation of the traceroute command in Python 3:
# If traceroute is not installed on your system, or blocked by your firewall,
# you can use the ping command to trace the route to a host.

import sys, time, subprocess

def traceroute_mac(hostname):
		print('traceroute to %s, 64 hops max, ~60 byte packets' % (hostname))
		for i in range(0, 64):
			start_time = time.time()			
			ping = subprocess.Popen(["ping", "-c", "1", "-t", "1", "-m", str(i), hostname], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
			end_time = time.time()
			time_taken = round((end_time - start_time) * 10000, 3)
			ping_out = ping.stdout.read().decode('utf-8')
			
			if 'exceeded' in ping_out:
				ip = ping_out.split('from')[1].split(':')[0]
				print('%s %s \t%s ms' % (i, ip, time_taken))

if __name__ == '__main__':
	traceroute_mac(sys.argv[1])