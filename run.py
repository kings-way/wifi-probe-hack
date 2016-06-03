#!/usr/bin/env python
# encoding=utf-8

import time
import pcap
import cStringIO
from multiprocessing import Process
import database
import os
import sys
import getopt


def get_mac(raw_data):
    return raw_data.encode('hex').upper()


def format_mac(mac):
    output = ""
    # Format MAC address like 'AABBCC001122' into 'AA:BB:CC:00:11:22'
    for i in range(0, 12, 2):
        output += (mac[i:i+2]+":")
    return output[0:-1]


def get_ssid(raw_data):

    # Get the length of ssid from the first 2 Bytes
    length = int(raw_data[0:2].encode('hex'), 16)

    # if length == 0, the SSID is Broadcast, we will return "Null"
    if length == 0:
        return "Null"
    else:
        try:
            ssid = raw_data[2:2+length].decode('utf8')
        except UnicodeDecodeError, info:
            sys.stderr.write("Error: SSID decode with utf8 Failed, " + str(info) + '\n')
            try:
                ssid = raw_data[2:2+length].decode('gbk')
            except UnicodeDecodeError, info:
                sys.stderr.write("Error: SSID decode with gbk Failed, " + str(info) + '\n')
                raise OSError
        return ssid


def get_model(raw_data):
    # This function get the device model from the packet.
    # But I do not have enough energy to analyse the whole packet in detail
    # I just search the packet for tag magic number. So, there could be some mistakes finding out the device model.

    # Tag: 0x1021, Manufacturer
    # Tag: 0x1023, Model Name
    # Tag: 0x1024, Model Number
    # Tag: 0x1011, Device Name

    raw_data_hex = raw_data.encode('hex')
    tag_1021 = raw_data_hex.find('1021')
    tag_1023 = raw_data_hex.find('1023')
    # tag_1024 = raw_data_hex.find('1024')

    if 0 < tag_1021 < tag_1023:
        vendor_length = int(raw_data_hex[tag_1021+4:tag_1021+8], 16)
        vendor_name = raw_data[(tag_1021+8)/2:(tag_1021+8)/2+vendor_length].decode('utf8')

        model_length = int(raw_data_hex[tag_1023+4:tag_1023+8], 16)
        model_name = raw_data[(tag_1023+8)/2:(tag_1023+8)/2+model_length].decode('utf8')

        if model_name.find(vendor_name) > -1:
            return model_name
        else:
            return vendor_name + model_name


def capture(if_mon):
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
        # compute the start of src mac address by the header length of packet
        # [Header revision], 1 Byte
        # [Header pad], 1 Byte
        # [Header length], 2 Bytes, mostly use the first byte
        # [Header body], xxx Bytes
        # [SubType and flags], 4 Bytes
        # [Dest addr], 6 Bytes, usually ff:ff:ff:ff:ff:ff
        # [Src addr], 6 Bytes
        # [Broadcast], 6 Bytes, usually ff:ff:ff:ff:ff:ff
        # [Sequence number], 2 Bytes
        # [Tag : SSID], 1 Byte
        # [Tag length], 1 Byte
        # [SSID body], xxx Bytes
        header_length = int(raw_data[2].encode('hex'), 16)
        mac_start_pos = 2 + 2 + header_length + 6

        mac = get_mac(raw_data[mac_start_pos:mac_start_pos+6])
        model = get_model(raw_data[mac_start_pos+12+2:])
        ssid = get_ssid(raw_data[mac_start_pos+12+2:])

        # Here, we call database.operate() to add some record.
        # Kinds of filter works will be done there.

        if flag_test:
            print local_time[10:], mac,  database.get_vendor(mac), ssid
        else:
            database.operate(mac, model, ssid, unix_time, local_time)


def display(refresh_interval=1, time_span=600, limit=100):
    """

    :param refresh_interval: int or float, refresh output interval (seconds)
    :param time_span: int, used to filter the stations that seen in the time_span (seconds)
    :param limit: int, used to limit rows of output
    """

    # Sleep for 1 seconds to make time for p_cap exit if it runs into error
    time.sleep(1)
    while True:
        #  '\033c' can flush output in VT compatible terminal, it works better than command 'clear'
        print '\033c'
        print "################################################# %s ##############################################" % time.strftime('%X', time.localtime(time.time()))
        print "%-13s%-20s%-55s%-80s\n" % ("[ Last Seen ]", "[ Source MAC ]", "[ Manufacturer ]",  "[ Probe SSID ]")
        rows = database.get_recent_station(int(time.time()), time_span, limit)
        for row in rows:
            # if model does not exist, then we display vendor instead
            if not row[2]:
                Manufacturer = row[1]
            else:
                Manufacturer = row[2]
            print "%-13s%-20s%-55s" % (row[4][10:], format_mac(row[0]), Manufacturer),

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
    database.init_tables()
    try:
        opts, args = getopt.getopt(sys.argv[1:], 'i:h', ["time=", "interval=", "limit=",  "help", "test"])
    except getopt.GetoptError:
        print "Error in args"
        quit(0)

    flag_test = False
    time_span = 600
    refresh_interval = 9
    limit = 50

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

    p_cap = Process(target=capture, args=[interface])
    p_cap.daemon = True
    p_cap.start()


    if flag_test:
        p_cap.join()
    else:
        # start the display process
        p_display = Process(target=display, args=(refresh_interval, time_span, limit))
        p_display.daemon = True
        p_display.start()

        # Wait until the p_cap process exits
        p_cap.join()
        database.destroy()






