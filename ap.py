#!/usr/bin/env python
# encoding=utf8

import subprocess
import os
import sys
import time
import signal
from multiprocessing import Process
from database import Database
from interface import iptables_nat


class AP:
    def __init__(self, mon):
        self.mon = mon
        self.stations = []
        self.ssids = []
        self.db = Database()
        self.airbase_process = Process(target=self.launch_airbase)
        self.airbase_process.daemon = True
        self.airbase_process.start()

    # deduplicate the ssids
    def deduplicate_ssids(self):
        self.ssids = list(set(self.ssids))

    def add_ssid(self, ssid):
        self.ssids.append(ssid)
        self.deduplicate_ssids()
        self.reload()

    def remove_ssid(self, ssid):
        self.ssids.remove(ssid)
        self.reload()

    def add_station(self, station_mac):
        station_mac = station_mac.replace(':', '').upper()
        all_ssid = self.db.get_allssid_by_mac(station_mac)
        for i in all_ssid:
            self.ssids.append(i[0])
        self.deduplicate_ssids()
        self.stations.append(station_mac)
        self.reload()

    def remove_station(self, station_mac):
        station_mac = station_mac.replace(':', '').upper()
        all_ssid = self.db.get_allssid_by_mac(station_mac)
        for i in all_ssid:
            self.ssids.remove(i[0])
        self.stations.remove(station_mac)
        self.reload()

    def reload(self):
        ssid_file = open('/tmp/ssid_file', 'w+')
        for i in self.ssids:
            ssid_file.write(i.encode('utf8')+'\n')
        ssid_file.close()
        print 'pid: ', self.airbase_process.pid

        # the real pid of airbase-ng process = airbase_process.pid + 1...
        os.kill(self.airbase_process.pid+1, signal.SIGUSR1)

    def launch_airbase(self):
        # The default ssid at startup...
        ssid_file = open('/tmp/ssid_file', 'w+')
        ssid_file.write('default\n')
        ssid_file.close()

        # Here, we are not using os.system(), cause we do not want run it in a shell
        subprocess.call(['./bin/airbase-ng_static', '--essids', '/tmp/ssid_file', self.mon])

    @staticmethod
    def stop():
        subprocess.call(['killall', 'airbase-ng_static'])


def signal_handler(signal, frame):
    print 'Exiting now...'
    AP.stop()
    sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print "########################################"
    print "    Now you can do things below:\n"
    print "  ap.add_ssid('Wifi')\t\t---- Add a ssid to broadcast. "
    print "  ap.remove_ssid('Wifi')\t---- Stop broadcast the ssid"
    print "  ap.add_station('MAC')\t\t---- Add a target station, all the ssid probed by this station will be broadcast"
    print "  ap.remove_station('MAC')\t---- Remove a target station..."
    print "  ap.stop()\t\t\t---- Stop the AP. Or you can just exit directly\n"

    mon = raw_input('Please specific the monitor wlan interface(wlanX?): ')
    wan = raw_input('Please specific the interface to be used for NAT Internet Access(ethX?): ')

    ap = AP(mon)
    time.sleep(1)
    os.system('ifconfig at0 192.168.11.1/24')
    os.system('ifconfig at0 up')
    iptables_nat(True, 'at0', wan)


