#!/usr/bin/env python
# encoding=utf-8

"""
Compute the start of Source MAC address by the header length of packet
    [Header revision], 1 Byte
    [Header pad], 1 Byte
    [Header length], 2 Bytes, mostly use the first byte
    [Header body], xxx Bytes
    [SubType and flags], 4 Bytes
    [Dest MAC], 6 Bytes, usually ff:ff:ff:ff:ff:ff
    [Src MAC], 6 Bytes
    [Broadcast], 6 Bytes, usually ff:ff:ff:ff:ff:ff
    [Sequence number], 2 Bytes
    [Tag : SSID], 1 Byte
    [Tag length], 1 Byte
    [SSID body], xxx Bytes
"""

import sys

# global variable
start_of_mac = 0


def set_start_of_mac(raw_data):
    # First called by get_mac() to set the global variable start_of_mac
    global start_of_mac
    # Get the start of Source MAC Address
    header_length = int(raw_data[2].encode('hex'), 16)
    start_of_mac = 2 + 2 + header_length + 6


def get_mac(raw_data):
    global start_of_mac
    # Call set_start_of_mac to set the global variable
    set_start_of_mac(raw_data)
    return raw_data[start_of_mac:start_of_mac + 6].encode('hex').upper()


def get_ssid(raw_data):
    global start_of_mac
    # Get the start of SSID Tag
    start_of_ssid = start_of_mac + 6 + 6 + 2
    raw_data = raw_data[start_of_ssid:]

    # Get the length of ssid from the first 2 Bytes
    length = int(raw_data[0:2].encode('hex'), 16)

    # if length == 0, the SSID is Broadcast, we will return "Null"
    if length == 0:
        return "Null"
    else:
        try:
            ssid = raw_data[2:2+length].decode('utf8')
        except UnicodeDecodeError, info:
            sys.stderr.write("Error: Failed to decode SSID with UTF8\nDetail:" + str(info) + '\n')
            try:
                ssid = raw_data[2:2+length].decode('gbk')
            except UnicodeDecodeError, info:
                sys.stderr.write("Error: Failed to decode SSID with GBK\nDetail:" + str(info) + '\n')
                sys.exit(-1)
        return ssid


def get_model(raw_data):
    global start_of_mac
    # This function get the device model from the packet.
    # But I do not have enough energy to analyse the whole packet in detail
    # I just search the packet for tag magic number. So, there could be some mistakes finding out the device model.

    # Tag: 0x1021, Manufacturer
    # Tag: 0x1023, Model Name
    # Tag: 0x1024, Model Number
    # Tag: 0x1011, Device Name

    # First we cut the useless part of packet
    raw_data = raw_data[start_of_mac + 12 + 2:]
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
