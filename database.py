#!/usr/bin/env python
# encoding=utf-8

import sqlite3
import re


class Database:
    def __init__(self):
        self.conn_main = sqlite3.connect('main.sqlite')
        self.cursor_main = self.conn_main.cursor()
        self.conn_oui = sqlite3.connect('oui.sqlite')
        self.cursor_oui = self.conn_oui.cursor()

        # Table t_station used to store information of each station(client)
        # Not include the probe ssid
        self.cursor_main.execute('create table IF NOT EXISTS t_station('
                            'mac varchar(12) PRIMARY KEY UNIQUE,'
                            'vendor varchar(110),'
                            'model varchar(40),'
                            'unix_time INT,'
                            'local_time varchar(20)'
                            ')')

        # Table t_ssid used to save ssid of every station
        # Each ssid may have more than one entries with different station mac addresses
        self.cursor_main.execute('create table IF NOT EXISTS t_ssid('
                            'station_mac VARCHAR(12),'
                            'ssid varchar(66)'
                            ')')
        self.conn_main.commit()

    def get_recent_station(self, now_time, time_span, limit):
        self.cursor_main.execute('select * from t_station where ((%d - unix_time) < %d) and vendor != "Unknown" order by unix_time DESC limit %d ' % (now_time, time_span, limit))
        self.conn_main.commit()
        return self.cursor_main.fetchall()

    def get_allssid_by_mac(self, mac):
        self.cursor_main.execute('select ssid from t_ssid where station_mac=?', [mac])
        self.conn_main.commit()
        return self.cursor_main.fetchall()

    def operate(self, mac, model, ssid, unix_time, local_time):

        # if this mac not recorded ever, then insert into t_station and t_ssid
        if not self.isInStation(mac):

            # First we find out the vendor
            vendor = self.get_vendor(mac)

            # Now insert a new entry
            self.cursor_main.execute('insert into t_station values(?,?,?,?,?)', (mac, vendor, model, unix_time, local_time))

            # do not store the ssid "Null"
            if ssid != "Null":
                self.cursor_main.execute('insert into t_ssid values(?,?)', (mac, ssid))

        # if this mac has been recorded in database,
        # but the (mac, ssid) pair has not been recorded, then insert into t_ssid
        elif not self.isInSsid(mac, ssid) and ssid != "Null":
            self.cursor_main.execute('insert into t_ssid values(?,?)', (mac, ssid))

        # if the (mac, ssid) pair has been recorded, then update the unix_time and local_time
        else:
            self.cursor_main.execute('update t_station set unix_time=?,local_time=? where mac=?', (unix_time, local_time, mac))
        self.conn_main.commit()

    def isInStation(self, mac):
        self.cursor_main.execute('select * from t_station where mac=?', [mac])
        self.conn_main.commit()
        if not self.cursor_main.fetchall():
            return False
        else:
            return True

    def isInSsid(self, mac, ssid):
        self.cursor_main.execute('select * from t_ssid where station_mac=? and ssid=?', (mac, ssid))
        self.conn_main.commit()
        if not self.cursor_main.fetchall():
            return False
        else:
            return True

    def get_vendor(self, mac):
        vendor = "Unknown"
        mac = mac.replace(":", "")
        mac = mac[0:6]
        self.cursor_oui.execute('select vendor_name from vendor where vendor_mac = ?', [mac])
        self.conn_oui.commit()
        row = self.cursor_oui.fetchone()
        if row:
            vendor = row[0]
        return vendor

    def gengrate_oui_db(self):
        # This function generate oui database from oui files
        self.cursor_oui.execute('DROP TABLE  IF EXISTS vendor')
        self.cursor_oui.execute('CREATE TABLE IF NOT EXISTS vendor('
                           'vendor_mac varchar(6) UNIQUE PRIMARY KEY ,'
                           'vendor_name varchar(110)'
                           ')')
        self.conn_oui.commit()

        # I got 2 oui files: /var/lib/ieee-data/oui.txt and /usr/share/ieee-data/oui.txt
        # For me, /var/lib/ieee-data/oui.txt has more entries than another
        oui_file = file('/usr/share/ieee-data/oui.txt')

        for line in oui_file:
            result = re.search('([0-9A-F]{2}-){2}[0-9A-F]{2}', line)
            if result:
                line = oui_file.next().decode('utf8')
                vendor_mac = line[2:8]
                vendor_name = line[line.find(')') + 1:].strip()

                # Only store the entry that has not been stored
                if self.get_vendor(vendor_mac) == "Unknown":
                    self.cursor_oui.execute('insert into vendor values(?,?)', (vendor_mac, vendor_name))
                    self.conn_oui.commit()
        oui_file.close()

    def destroy(self):
        self.conn_main.close()
        self.conn_oui.close()
