#!/usr/bin/env python
# encoding=utf8

import subprocess
from multiprocessing import Process
from database import Database


class AP:
    def __init__(self, mon_interface):
        self.mon_interface = mon_interface
        self.stations = []
        self.ssids = []
        self.db = Database()
        self.airbase_process = None

    # deduplicate the ssids
    def deduplicate_ssids(self):
        self.ssids = list(set(self.ssids))

    def add_ssid(self, ssid):
        self.ssids.append(ssid)
        self.deduplicate_ssids()
        self.start()

    def remove_ssid(self, ssid):
        self.ssids.remove(ssid)
        if len(self.ssids) > 0:
            self.start()
        else:
            self.stop()

    def add_station(self, station_mac):
        station_mac = station_mac.replace(':', '').upper()
        all_ssid = self.db.get_allssid_by_mac(station_mac)
        for i in all_ssid:
            self.ssids.append(i[0])
        self.deduplicate_ssids()
        self.stations.append(station_mac)
        self.start()

    def remove_station(self, station_mac):
        station_mac = station_mac.replace(':', '').upper()
        all_ssid = self.db.get_allssid_by_mac(station_mac)
        for i in all_ssid:
            self.ssids.remove(i[0])
        self.stations.remove(station_mac)
        if len(self.ssids) > 0:
            self.start()
        else:
            self.stop()

    def start(self):
        ssid_file = open('/tmp/ssid_file', 'w+')
        for i in self.ssids:
            ssid_file.write(i.encode('utf8')+'\n')
        ssid_file.close()

        # this is None when first run...
        if self.airbase_process == None:
            print "the process is None"
            self.airbase_process = Process(target=self.launch_airbase)

        elif self.airbase_process.is_alive():
            # We are going to kill the former process
            # But the terminate() function does not work and the exitcode always be -15...
            # self.airbase_process.terminate()
            self.stop()
            self.airbase_process = Process(target=self.launch_airbase)

        self.airbase_process.daemon = True
        self.airbase_process.start()

    def stop(self):
        subprocess.call(['killall', 'airbase-ng'])

    def launch_airbase(self):
        # Here, we are not using os.system(), cause we do not want run it in a shell
        subprocess.call(['./bin/airbase-ng', '--essids', '/tmp/ssid_file', self.mon_interface])

if __name__ == '__main__':
    tmp_file = open('/tmp/interface_name_by_wifi_probe_hack', 'r')
    mon_interface = tmp_file.readline().strip()
    tmp_file.close()

    ap = AP(mon_interface)
    print "########################################"
    print "    Now you can do things below:\n"
    print "  ap.add_ssid('Wifi')\t\t---- Add a ssid to broadcast. "
    print "  ap.remove_ssid('Wifi')\t---- Stop broadcast the ssid"
    print "  ap.add_station('MAC')\t\t---- Add a target station, all the ssid probed by this station will be broadcast"
    print "  ap.remove_station('MAC')\t---- Remove a target station..."
    print "  ap.stop()\t\t\t---- Stop the AP. Or you can just exit directly\n"


