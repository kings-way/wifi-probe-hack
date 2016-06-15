import os
import sys
import time
import commands


def set_monitor(interface, flag):

    # Notice:
    # 1.  Although there is a lib called python-wifi supplying some operations on wlan interfaces,
    #     but it does not support the up/down operation on interfaces.
    # 2.  Using iw instead of iwconfig, because iwconfig does not work well with mac80211 subsystem
    # 3.  Not using try-except because the errors may have already handled by system commands
    if flag:
        return_value = os.system('/sbin/iw ' + interface + ' set type monitor')

        # sleep for 0.5 seconds and then check whether monitor mode set successfully
        time.sleep(0.5)
        if commands.getoutput('/sbin/iw ' + interface + ' info').find('monitor') == -1:

            choice = raw_input('Failed to set ' + interface + 'into monitor mode. Are you sure to kill NetworkManager (Y/n) ?')
            if choice == 'n':
                print 'Exiting now...'
                sys.exit(-1)
            else:
                os.system('service network-manager stop')
                # now set monitor mode again
                return_value += os.system('/sbin/iw ' + interface + ' set type monitor')
        return_value += os.system('/sbin/ifconfig ' + interface + ' up')

    else:
        print "restore network...."
        return_value = os.system('/sbin/ifconfig ' + interface + ' down')
        return_value += os.system('/sbin/iw ' + interface + ' set type managed')

        # I am not sure this service start command will work on other distributions
        return_value += os.system('service network-manager start')

    if return_value != 0:
        print "\tFailed to prepare the interface..."
        sys.exit(-1)

def iptables_nat(flag, in_int, out_int):

    if flag:
        os.system('iptables -A FORWARD -i ' + in_int + ' -o ' + out_int + ' -j ACCEPT')
        os.system('iptables -t nat -A POSTROUTING -o ' + out_int + ' -j MASQUERADE')
    # Flush the iptables may destroy some configurations on someone's OS...
    # else:
        # os.system('iptables -F')
        # os.system('iptables -t nat -F')