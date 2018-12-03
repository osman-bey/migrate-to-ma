import yaml
import re
from datetime import datetime
from devclass import *
import os
# from getpass import getpass


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

    username = "cisco"      # input("Enter login: ")
    password = "cisco"      # getpass()
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
        tries = 2
        for i in range(tries):
            try:
                print("{ip:17}{host:25}{comment:22}queue length: {qlen}\r".format(ip=device.ip_address,
                                                                                  host=device.hostname,
                                                                                  qlen=qlenth,
                                                                                  comment=""))
                device.connect(username, password)
                get_arp(device)
                get_config(device)
                device.configure(device.config)
                ping_arp(device)
                ping_ma_check(device)
                device.commit()
                device.disconnect()
                q.task_done()
                print("{ip:17}{host:25}{comment:22}queue length: {qlen}\r".format(ip=device.ip_address,
                                                                                  host=device.hostname,
                                                                                  qlen=qlenth,
                                                                                  comment="done"))

            except Exception as err_msg:
                if i < tries - 1:
                    print("{ip:17}{host:25}{comment:19}{tries:<3}queue length: {qlen}\r".format(ip=device.ip_address,
                                                                                                host=device.hostname,
                                                                                                qlen=qlenth,
                                                                                                comment="attempt no:",
                                                                                                tries=(i+2)))
                    continue

                else:
                    device.fconnect = True
                    device.fconnect_msg = err_msg
                    print("{0:17}{1:25}{2:20}".format(device.ip_address, device.hostname, "connection failed"))
                    q.task_done()

            break


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

rtn_vlan_list = ["Vlan" + str(i) for i in range(4000, 4021)]


def get_config(device):

    inf_config = device.get_inf_config()

    cmd_template = "interface {0}\n" \
                   "no ip address\n" \
                   "no vrf forwarding\n" \
                   "vrf forwarding MA\n" \
                   "ip address {1}"

    cmd_template_helper = "interface {0}\n" \
                          "{2}\n" \
                          "no ip address\n" \
                          "no vrf forwarding\n" \
                          "vrf forwarding MA\n" \
                          "ip address {1}\n" \
                          "{3}"

    allowed_vrf_list = ["ABIS", "IUB", "OAM", "S1U", "S1MME", "X2"]

    inf_config_list = []
    inf_count = -1

    '''
    inf_config_list = {
    vlan : Vlan1000
    vrf: ABIS
    ipmask: 10.165.208.193 255.255.255.240
    hlp: [172.20.17.181, 172.20.17.182]
    }
    '''

    vlan_pattern = re.compile(r"interface (Vlan\d*)")
    ip_pattern = re.compile(r"ip address ([0-9.]+\s[0-9.]+)")
    helper_pattern = re.compile(r"ip helper-address ([0-9.]+)")
    vrf_pattern = re.compile(r"vrf forwarding (.*)")

    for line in inf_config.splitlines():

        if "interface Vlan" in line:
            inf_count += 1
            inf_config_list.append({})

            inf_match = re.search(vlan_pattern, line)
            if inf_match:
                inf_config_list[inf_count]["vlan"] = inf_match.group(1)

        else:
            ip_match = re.search(ip_pattern, line)
            hlp_match = re.search(helper_pattern, line)
            vrf_match = re.search(vrf_pattern, line)
            if ip_match:
                inf_config_list[inf_count]["ipmask"] = ip_match.group(1)
            if vrf_match:
                inf_config_list[inf_count]["vrf"] = vrf_match.group(1)
            if hlp_match:
                if inf_config_list[inf_count].get("hlp"):
                    inf_config_list[inf_count]["hlp"].append(hlp_match.group(1))
                else:
                    inf_config_list[inf_count]["hlp"] = []
                    inf_config_list[inf_count]["hlp"].append(hlp_match.group(1))

    for cfg in inf_config_list:

        if cfg["vlan"] not in rtn_vlan_list and cfg["vrf"] in allowed_vrf_list:
            if cfg.get("hlp"):
                nohelper_list = []
                helper_list = []

                for iphlp in cfg["hlp"]:
                    nohelper_list.append("no ip helper-address {}".format(iphlp))
                    helper_list.append("ip helper-address {}".format(iphlp))

                nohelper_cmd = "\n".join(nohelper_list)
                helper_cmd = "\n".join(helper_list)
                cmd = cmd_template_helper.format(cfg["vlan"], cfg["ipmask"], nohelper_cmd, helper_cmd)
                for j in cmd.splitlines():
                    device.config.append(j)
            else:
                cmd = cmd_template.format(cfg["vlan"], cfg["ipmask"])
                for j in cmd.splitlines():
                    device.config.append(j)

        else:               # if vlan in 4000-4020
            pass


def get_arp(device):

    abis_arp_log = device.show_arp_abis()
    iub_arp_log = device.show_arp_iub()
    oam_arp_log = device.show_arp_oam()
    s1u_arp_log = device.show_arp_s1u()
    s1mme_arp_log = device.show_arp_s1mme()
    x2_arp_log = device.show_arp_x2()

    # Internet  10.166.28.33            -   aabb.cc80.2000  ARPA   Vlan4001

    for i in abis_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
                device.arp_abis.append(arp_list[1])
                device.arp_ma.append(arp_list[1])

    for i in iub_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
                device.arp_iub.append(arp_list[1])
                device.arp_ma.append(arp_list[1])

    for i in oam_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
                device.arp_oam.append(arp_list[1])
                device.arp_ma.append(arp_list[1])

    for i in s1u_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
                device.arp_s1u.append(arp_list[1])
                device.arp_ma.append(arp_list[1])

    for i in s1mme_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
                device.arp_s1mme.append(arp_list[1])
                device.arp_ma.append(arp_list[1])

    for i in x2_arp_log.splitlines():
        if "Incomplete" not in i:
            arp_list = i.strip().split()
            if arp_list[2] is not "-" and arp_list[5] not in rtn_vlan_list:
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
        print("{:89}{}\r".format("", "ping is failed"))
