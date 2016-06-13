#!/usr/bin/env python
# encoding=utf-8

import time
import pcap
from multiprocessing import Process
from database import Database
from interface import set_monitor
import sys
import signal
import getopt
import decode


def format_mac(mac):
    output = ""
    # Format MAC address like 'AABBCC001122' into 'AA:BB:CC:00:11:22'
    for i in range(0, 12, 2):
        output += (mac[i:i+2]+":")
    return output[0:-1]


def capture(mon_interface):
    global flag_test
    """
    :type if_mon: string,  name of the interface operating in monitor mode
    """
    try:
        pc = pcap.pcap(mon_interface)
        pc.setfilter('subtype probereq')
    except Exception, info:
        sys.stderr.write("\nError: " + str(info) + "\n")
        quit(0)

    for unix_time, packet_buf in pc:
        unix_time = int(unix_time)
        local_time = time.localtime(unix_time)
        local_time = time.strftime('%Y/%m/%d %X', local_time)
        raw_data = str(packet_buf)

        mac = decode.get_mac(raw_data)
        model = decode.get_model(raw_data)
        ssid = decode.get_ssid(raw_data)

        # Here, we call db.operate() to add some record.
        # Kinds of filter works will be done there.
        if flag_test:
            print local_time[10:], mac,  db.get_vendor(mac), ssid
            db.operate(mac, model, ssid, unix_time, local_time)
        else:
            db.operate(mac, model, ssid, unix_time, local_time)


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
        rows = db.get_recent_station(int(time.time()), time_span, limit)
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
            for ssid in db.get_allssid_by_mac(row[0]):
                ssid_all += ssid[0]+","
                count += 1
                # display 6 ssid in one line
                if count % 6 == 0:
                    ssid_all += "\n%89s" % ""

            # print without the last ','
            print ssid_all.strip()[:-1]
        time.sleep(refresh_interval)


def signal_handler(signal, frame):
    print "exiting now..."
    p_cap.terminate()
    if not flag_test:
        p_display.terminate()
    set_monitor(interface, False)
    db.destroy()


if __name__ == '__main__':

    # refresh_interval: int or float, refresh output interval (seconds)
    # time_span:        int, used to filter the stations that seen in the time_span (seconds)
    # limit:            int, used to limit rows of output
    # flag_test:        boolean, for test use only

    # TODO: finish the help menu
    # TODO: check if every necessary options provided

    refresh_interval = 2
    time_span = 600
    limit = 50
    flag_test = False

    db = Database()
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
            print "######## HELP ########"
            quit(0)
        elif opt == '--test':
            flag_test = True

    set_monitor(interface, True)
    mon_interface = interface + '_mon'
    p_cap = Process(target=capture, args=[mon_interface])
    p_cap.daemon = True
    p_cap.start()

    if not flag_test:
        # start the display process
        p_display = Process(target=display)
        p_display.daemon = True
        p_display.start()

    # register signal handle function and wait for a signal
    signal.signal(signal.SIGINT, signal_handler)
    signal.pause()


