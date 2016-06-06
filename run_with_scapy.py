#!/usr/bin/env python
# encoding=utf-8
import os
import time
from multiprocessing import Process
import database
import sys
import signal
import getopt
import decode
from scapy.layers.dot11 import Dot11Elt
import scapy.all as scapy


def format_mac(mac):
    output = ""
    # Format MAC address like 'AABBCC001122' into 'AA:BB:CC:00:11:22'
    for i in range(0, 12, 2):
        output += (mac[i:i+2]+":")
    return output[0:-1]


def on_receiving(packet):
    if Dot11Elt in packet:
        ssid = packet[Dot11Elt].info
        if not ssid:
            ssid = 'Null'
        mac = packet.addr2.upper().replace(':', '')
        unix_time = int(time.time())
        local_time = time.localtime(unix_time)
        local_time = time.strftime('%Y/%m/%d %X', local_time)
        model = decode.get_model(str(packet))

        # Here, we call database.operate() to add some record.
        # Kinds of filter works will be done there.
        if flag_test:
            print local_time[10:], mac,  database.get_vendor(mac), ssid
            database.operate(mac, model, ssid, unix_time, local_time)
        else:
            database.operate(mac, model, ssid, unix_time, local_time)


def capture(if_mon):
    global flag_test
    """
    :type if_mon: string,  name of the interface operating in monitor mode
    """
    try:
        scapy.conf.iface=if_mon
        scapy.sniff(iface=if_mon, prn=on_receiving, store=0, filter="subtype probereq")
    except Exception, info:
        sys.stderr.write("\nError: " + str(info) + "\n")
        quit(0)


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


def set_interface(if_name, flag):
    # Notice:
    # 1.  Although there is a lib called python-wifi supplying some operations on wlan interfaces,
    #     but it does not support the up/down operation on interfaces.
    # 2.  Using iw instead of iwconfig, because iwconfig does not work well with mac80211 subsystem
    # 3.  Not using try-except because the errors may have already handled by system commands
    if flag:
        return_value = os.system('/sbin/ifconfig ' + if_name + ' down')
        # return_value += os.system('/sbin/iwconfig ' + if_name + ' mode Monitor')
        return_value += os.system('/sbin/iw ' + if_name + ' set type monitor')
        return_value += os.system('/sbin/ifconfig ' + if_name + ' up')
    else:
        return_value = os.system('/sbin/ifconfig ' + interface + ' down')
        # return_value += os.system('/sbin/iwconfig ' + interface + ' mode Managed')
        return_value += os.system('/sbin/iw ' + interface + ' set type managed')
        return_value += os.system('/sbin/ifconfig ' + interface + ' up')
    if return_value != 0:
        print "\tFailed to prepare the interface..."
        sys.exit(-1)


def signal_handler(signal, frame):
    print "Exiting now"
    p_cap.terminate()
    p_display.terminate()
    set_interface(interface, False)
    database.destroy()


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
            print "######## HELP ########"
            quit(0)
        elif opt == '--test':
            flag_test = True

    set_interface(interface, True)
    p_cap = Process(target=capture, args=[interface])
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


