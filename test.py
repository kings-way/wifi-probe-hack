#!/usr/bin/env python

from pythonwifi.iwlibs import Wireless
import os

if __name__ == "__main__":
    interface = "wlan1"
    wifi = Wireless(interface)
    print wifi.getMode()
    print wifi.getMode()
    wifi.setMode('Monitor')
    print wifi.getMode()

