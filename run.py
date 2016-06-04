#!/usr/bin/env python
# encoding=utf-8

import time
import pcap
import cStringIO
from multiprocessing import Process
import database
import sys
import getopt
import decode


def format_mac(mac):
    output = ""
    # Format MAC address like 'AABBCC001122' into 'AA:BB:CC:00:11:22'
    for i in range(0, 12, 2):
        output += (mac[i:i+2]+":")
    return output[0:-1]


def capture(if_mon):
    global flag_test
    """
    :type if_mon: string,  name of the interface operating in monitor mode
    """
    try:
        pc = pcap.pcap(if_mon)
        pc.setfilter('subtype probereq')
    except Exception, info:
        sys.stderr.write("\nError: " + str(info) + "\n")
        quit(0)

    for unix_time, packet_buf in pc:
        unix_time = int(unix_time)
        local_time = time.localtime(unix_time)
        local_time = time.strftime('%Y/%m/%d %X', local_time)
        raw_data = cStringIO.StringIO(packet_buf).read()

        mac = decode.get_mac(raw_data)
        model = decode.get_model(raw_data)
        ssid = decode.get_ssid(raw_data)

        # Here, we call database.operate() to add some record.
        # Kinds of filter works will be done there.
        if flag_test:
            print local_time[10:], mac,  database.get_vendor(mac), ssid
            database.operate(mac, model, ssid, unix_time, local_time)
        else:
            database.operate(mac, model, ssid, unix_time, local_time)


def display():
    global refresh_interval
    global time_span
    global limit

    # Sleep for 1 seconds to make time for p_cap process exit if it runs into error
    time.sleep(1)
    while True:
        #  '\033c' can clear output in VT compatible terminal, it works better than the shell command 'clear'
        print '\033c'
        print "################################################# %s ##############################################" \
              % time.strftime('%X', time.localtime(time.time()))
        print "%-13s%-20s%-55s%-80s\n" % ("[ Last Seen ]", "[ Source MAC ]", "[ Manufacturer ]",  "[ Probe SSID ]")
        rows = database.get_recent_station(int(time.time()), time_span, limit)
        for row in rows:
            # if model does not exist, then we display vendor instead
            if not row[2]:
                manufacturer = row[1]
            else:
                manufacturer = row[2]
            print "%-13s%-20s%-55s" % (row[4][10:], format_mac(row[0]), manufacturer),

            # display the ssid takes some more code ....
            count = 0
            ssid_all = ""
            for ssid in database.get_allssid_by_mac(row[0]):
                ssid_all += ssid[0]+","
                count += 1
                # display 6 ssid in one line
                if count % 6 == 0:
                    ssid_all += "\n%89s" % ""

            # print without the last ','
            print ssid_all.strip()[:-1]
        time.sleep(refresh_interval)


if __name__ == '__main__':
    # some global variables
    refresh_interval = 2
    time_span = 600
    limit = 50
    flag_test = False
    """
        refresh_interval: int or float, refresh output interval (seconds)
        time_span: int, used to filter the stations that seen in the time_span (seconds)
        limit: int, used to limit rows of output
        flag_test: boolean, for test use only
    """
    database.init_tables()

    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:h', ["time=", "interval=", "limit=",  "help", "test"])
    except getopt.GetoptError:
        print "Error in args"
        quit(0)

    for opt, value in opts:
        if opt == '-i':
            interface = value
        elif opt == '--time':
            time_span = int(value)
        elif opt == '--interval':
            refresh_interval = int(value)
        elif opt == '--limit':
                limit = int(value)
        elif opt in ('-h', '--help'):
            # TODO： Help Menu
            print "######## HELP ########"
            quit(0)
        elif opt == '--test':
            flag_test = True

    p_cap = Process(target=capture, args=[interface])
    p_cap.daemon = True
    p_cap.start()

    if flag_test:
        p_cap.join()
    else:
        # start the display process
        p_display = Process(target=display)
        p_display.daemon = True
        p_display.start()

        # Wait until the p_cap process exits
        p_cap.join()
        database.destroy()

