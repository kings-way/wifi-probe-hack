import os
import sys
import time
import commands


def set_interface(interface, flag):
    mon_interface = interface + '_mon'
    # Notice:
    # 1.  Although there is a lib called python-wifi supplying some operations on wlan interfaces,
    #     but it does not support the up/down operation on interfaces.
    # 2.  Using iw instead of iwconfig, because iwconfig does not work well with mac80211 subsystem
    # 3.  Not using try-except because the errors may have already handled by system commands
    if flag:
        return_value = os.system('/sbin/iw ' + interface + ' interface add ' + mon_interface + ' type monitor')

        # sleep for 1 seconds and then check whether monitor mode set successfully
        time.sleep(1)
        if commands.getoutput('/sbin/iw ' + mon_interface + ' info').find('monitor') == -1:

            choice = raw_input('Failed to set ' + mon_interface + 'into monitor mode. Are you sure to kill NetworkManager (Y/n) ?')
            if choice == 'n':
                os.system('/sbin/iw ' + mon_interface + ' del')
                print 'Exiting now...'
                sys.exit(-1)
            else:
                os.system('service network-manager stop')
                # now set monitor mode again
                return_value += os.system('/sbin/iw ' + mon_interface + ' set type monitor')
        return_value += os.system('/sbin/ifconfig ' + mon_interface + ' up')

    else:
        print "restore network...."
        return_value = os.system('/sbin/ifconfig ' + mon_interface + ' down')
        return_value += os.system('/sbin/iw ' + mon_interface + ' del')

        # I am not sure this service start command will work on other distros
        return_value += os.system('service network-manager start')

    if return_value != 0:
        print "\tFailed to prepare the interface..."
        sys.exit(-1)