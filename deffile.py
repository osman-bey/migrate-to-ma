import yaml
import re
from datetime import datetime
from devclass import *
import os
from getpass import getpass
import xml.etree.ElementTree as ET


#######################################################################################
# ------------------------------ def function part -----------------------------------#
#######################################################################################

def get_argv(argv):

    argv_dict = {"maxth": 10}
    mt_pattern = re.compile(r"mt([0-9]+)")

    for i in argv:
        if "mt" in i:
            match = re.search(mt_pattern, i)
            if match and int(match.group(1)) <= 100:
                argv_dict["maxth"] = int(match.group(1))

    print("")
    return argv_dict


def get_user_pw():

    username = input("Enter login: ")
    password = getpass()
    print("")
    return username, password


def get_devinfo(yaml_file):

    devices = []
    file = open(yaml_file, "r")
    devices_info = yaml.load(file)

    for hostname, ip_address in devices_info.items():
        device = NetworkDeviceIOS(ip=ip_address, host=hostname)
        devices.append(device)

    file.close()
    print("")
    return devices


def mconnect(q, username, password):

    while True:
        device = q.get()
        qlenth = q.qsize()

        try:
            print("{1:17}{2:25}{0:22}queue length: {3}".format("", device.ip_address, device.hostname, qlenth))
            device.connect(username, password)

            get_arp(device)
            get_config(device, get_xml, make_config)
            device.configure(device.config)
            ping_arp(device)
            ping_ma_check(device)

            device.commit()
            device.disconnect()
            q.task_done()

        except Exception as err_msg:
            device.fconnect = True
            device.fconnect_msg = err_msg
            print("{0:17}{1:25}{2:20}".format(device.ip_address, device.hostname, "connection failed"))
            q.task_done()


def write_logs(devices):

    count_fconnect = 0
    count_commit_error = 0
    count_ping_ma_error = 0

    current_dir = os.getcwd()
    now = datetime.now()
    current_year = now.year
    current_month = now.month
    current_day = now.day
    current_hour = now.hour
    current_minute = now.minute

    ping_ma_log_file = open(current_dir + r"\logs\ping_ma_logs.txt", "w")
    conf_logs_file = open(current_dir + r"\logs\conf.txt", "w")
    fconn_devices_logs_file = open(current_dir + r"\logs\failed_conn.txt", "w") 
    fconn_msg_logs_file = open(current_dir + r"\logs\failed_conn_msg.txt", "w")
    conf_error_devices_logs_file = open(current_dir + r"\logs\conf_error_devices.txt", "w")

    ping_ma_log_file.write(
        "{}.{:02d}.{:02d} {}:{}\n\n".format(current_year, current_month,
                                            current_day, current_hour, current_minute))

    conf_logs_file.write(
        "{}.{:02d}.{:02d} {}:{}\n\n".format(current_year, current_month,
                                            current_day, current_hour, current_minute))
    fconn_devices_logs_file.write(
        "{}.{:02d}.{:02d} {}:{}\n\n".format(current_year, current_month,
                                            current_day, current_hour, current_minute))
    conf_error_devices_logs_file.write(
        "{}.{:02d}.{:02d} {}:{}\n\n".format(current_year, current_month,
                                            current_day, current_hour, current_minute))
    fconn_msg_logs_file.write(
        "{}.{:02d}.{:02d} {}:{}\n\n".format(current_year, current_month,
                                            current_day, current_hour, current_minute))

    for device in devices:

        if device.fconnect is False:

            ping_ma_log_file.write("--------------------------------------------------------------------------------\n")
            ping_ma_log_file.write("--- {} : {}\n\n".format(device.ip_address, device.hostname))

            for i in device.ping_ma_log:
                ping_ma_log_file.write(i + "\n")

            ping_ma_log_file.write("\n\n")

            conf_logs_file.write("--------------------------------------------------------------------------------\n")
            conf_logs_file.write("--- {} : {}\n\n".format(device.ip_address, device.hostname))

            for i in device.conf_logs:
                conf_logs_file.write(i + "\n")

            conf_logs_file.write("\n\n")

            if "[OK]" not in device.conf_logs[-1]:
                count_commit_error += 1
                conf_error_devices_logs_file.write("{} : {} - {}\n".format(device.ip_address,
                                                                           device.hostname,
                                                                           "commit error"))
            if "Invalid input detected" in device.conf_logs[0]:
                count_commit_error += 1
                conf_error_devices_logs_file.write("{} : {} - {}\n".format(device.ip_address,
                                                                           device.hostname,
                                                                           "conf error"))

        if device.fconnect:

            count_fconnect += 1
            fconn_devices_logs_file.write("{} {}\n".format(device.ip_address, device.hostname))
            fconn_msg_logs_file.write("-"*120 + "\n")
            fconn_msg_logs_file.write("--- {} : {}\n\n".format(device.ip_address, device.hostname))
            fconn_msg_logs_file.write("{}\n".format(device.fconnect_msg))

        if device.ping_ma_status is False:
            count_ping_ma_error += 1


    conf_logs_file.close()
    fconn_devices_logs_file.close()
    conf_error_devices_logs_file.close()
    fconn_msg_logs_file.close()
    ping_ma_log_file.close()

    return count_fconnect, count_commit_error, count_ping_ma_error


#######################################################################################
# ------------------------------ test part -------------------------------------------#
#######################################################################################

def get_xml(vrf):

    remove_list = []
    input_list = vrf.splitlines()

    for i in input_list:
        if "Load for five secs" in i:
            remove_list.append(i)
        elif "Time source is NTP" in i:
            remove_list.append(i)
        elif i is "":
            remove_list.append(i)

    for i in remove_list:
        input_list.remove(i)

    input_list[0] = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Device-Configuration>"
    output = "\n".join(input_list)
    return output


def make_config(device, tree):

    cmd_template = "interface {0}\n" \
                   "no ip address\n" \
                   "no vrf forwarding\n" \
                   "vrf forwarding MA\n" \
                   "ip address {1} {2}"

    cmd_template_helper = "interface {0}\n" \
                          "{3}\n" \
                          "no ip address\n" \
                          "no vrf forwarding\n" \
                          "vrf forwarding MA\n" \
                          "ip address {1} {2}\n" \
                          "{4}"

    vlan_list = ["Vlan" + str(i) for i in range(4000, 4021)]

    for inf in tree.findall('interface'):

        nohelper_list = []
        helper_list = []

        vlan = inf.find('Param').text

        if vlan not in vlan_list:
            ipaddress = inf.find(".//IPAddress").text
            ipsubnetmask = inf.find(".//IPSubnetMask").text

            hlp = inf.findall(".//IPDestinationAddress")

            if len(hlp) is 0:
                cmd = cmd_template.format(vlan, ipaddress, ipsubnetmask)
            else:
                for iphlp in hlp:
                    nohelper_list.append("no ip helper-address {}".format(iphlp.text))
                    helper_list.append("ip helper-address {}".format(iphlp.text))
                    nohelper_cmd = "\n".join(nohelper_list)
                    helper_cmd = "\n".join(helper_list)

                    cmd = cmd_template_helper.format(vlan, ipaddress, ipsubnetmask, nohelper_cmd, helper_cmd)

            for j in cmd.splitlines():
                device.config.append(j)

        else:               # if vlan in 4000-4020
            pass

def get_config(device, def_xml, def_config):

    abis = device.get_abis()
    iub = device.get_iub()
    oam = device.get_oam()
    s1u = device.get_s1u()
    s1mme = device.get_s1mme()
    x2 = device.get_x2()

    abis_xml = def_xml(abis)
    iub_xml = def_xml(iub)
    oam_xml = def_xml(oam)
    s1u_xml = def_xml(s1u)
    s1mme_xml = def_xml(s1mme)
    x2_xml = def_xml(x2)

    abis_tree = ET.fromstring(abis_xml)
    iub_tree = ET.fromstring(iub_xml)
    oam_tree = ET.fromstring(oam_xml)
    s1u_tree = ET.fromstring(s1u_xml)
    s1mme_tree = ET.fromstring(s1mme_xml)
    x2_tree = ET.fromstring(x2_xml)

    def_config(device, abis_tree)
    def_config(device, iub_tree)
    def_config(device, oam_tree)
    def_config(device, s1u_tree)
    def_config(device, s1mme_tree)
    def_config(device, x2_tree)


def get_arp(device):

    abis_arp_log = device.show_arp_abis()
    iub_arp_log = device.show_arp_iub()
    oam_arp_log = device.show_arp_oam()
    s1u_arp_log = device.show_arp_s1u()
    s1mme_arp_log = device.show_arp_s1mme()
    x2_arp_log = device.show_arp_x2()

    for i in abis_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_abis.append(arp_list[1])
            device.arp_ma.append(arp_list[1])

    for i in iub_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_iub.append(arp_list[1])
            device.arp_ma.append(arp_list[1])

    for i in oam_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_oam.append(arp_list[1])
            device.arp_ma.append(arp_list[1])

    for i in s1u_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_s1u.append(arp_list[1])
            device.arp_ma.append(arp_list[1])

    for i in s1mme_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_s1mme.append(arp_list[1])
            device.arp_ma.append(arp_list[1])

    for i in x2_arp_log.splitlines():
        arp_list = i.strip().split()
        if arp_list[2] is not "-":
            device.arp_x2.append(arp_list[1])
            device.arp_ma.append(arp_list[1])


def ping_arp(device):

    if len(device.arp_ma) is not 0:
        for i in device.arp_ma:
            device.ping_ma_log.append(device.ping_ma(i))


def ping_ma_check(device):

    for i in device.ping_ma_log:
        for j in i.splitlines():
            if "Success rate is 0 percent" in j and device.ping_ma_status is True:
                device.ping_ma_status = False

    if device.ping_ma_status is False:
        print("{0:17}{1:25}{2:20}".format(device.ip_address, device.hostname, "ping is failed"))
