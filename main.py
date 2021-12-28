import yaml
import csv
import time
import queue
import re
from threading import Thread
from pprint import pformat
from openpyxl import load_workbook, Workbook, styles
from getpass import getpass
from sys import argv
from datetime import datetime, timedelta
from pathlib import Path
from netmiko import ConnectHandler
from netmiko.ssh_exception import NetMikoTimeoutException, SSHException

# решение проблемы при подключении к IOS XR
import logging
logging.getLogger('paramiko.transport').disabled = True 


#######################################################################################
# ------------------------------ classes part ----------------------------------------#
#######################################################################################


class CiscoIOS:
    def __init__(self, ip, host):
        self.hostname = host
        self.ip_address = ip
        self.ssh_conn = None
        self.os_type = "cisco_ios"

        self.connection_status = True       # failed connection status, False if connection fails
        self.connection_error_msg = None    # connection error message

        self.show_version = None
        self.show_inventory = None

        self.chassis = {"model": "-", "sn": "-"}
        self.pid = {}   # pid : s/n

    def show_commands(self):
        self.show_version = self.ssh_conn.send_command(r"show version")
        self.show_inventory = self.ssh_conn.send_command(r"show inventory")

    def parse(self):


    def reset(self):
        self.connection_status = True
        self.connection_error_msg = None
        self.show_version = None
        self.show_inventory = None
        self.chassis = {"model": "-", "sn": "-"}
        self.pid = {}   # pid : s/n


class CiscoXR(CiscoIOS):

    def __init__(self, ip, host):
        CiscoIOS.__init__(self, ip, host)
        self.os_type = "cisco_xr"

    def show_commands(self):
        self.show_version = self.ssh_conn.send_command(r"show version brief")
        self.show_inventory = self.ssh_conn.send_command(r"show inventory")



#######################################################################################
# ------------------------------ def function part -----------------------------------#
#######################################################################################


def get_arguments(arguments):
    settings = {"maxth": 20, "conf": False, "os_type": "cisco_ios"}
    mt_pattern = re.compile(r"mt([0-9]+)")
    for arg in arguments:
        if "mt" in arg:
            match = re.search(mt_pattern, arg)
            if match and int(match[1]) <= 100:
                settings["maxth"] = int(match[1])
        elif arg == "xr" or arg == "XR":
            settings["os_type"] = "cisco_xr"
  
    print("\n"
          f"max threads:...................{settings['maxth']}\n"
          f"OS:............................{settings['os_type']}\n"
          )
    return settings


def get_user_pw():
    user = input("Enter login: ")
    psw = getpass()
    print()
    return user, psw


def get_device_info(yaml_file, settings):
    devs = []
    with open(yaml_file, "r") as file:
        devices_info = yaml.load(file, yaml.SafeLoader)
        if settings["os_type"] == "cisco_ios":
            for hostname, ip_address in devices_info.items():
                dev = CiscoIOS(ip=ip_address, host=hostname)
                devs.append(dev)
        elif settings["os_type"] == "cisco_xr":
            for hostname, ip_address in devices_info.items():
                dev = PaggXR(ip=ip_address, host=hostname)
                devs.append(dev)

    return devs


def write_logs(devices, current_time, log_folder, settings):
    failed_conn_count = 0
    unavailable_device = []
    devices_with_cfg = []
    unknown_mac = []
    tag_hostname = {}
    bs_hostname = {}

    export_excel(devices, current_time, log_folder)

    conn_msg = log_folder / f"{current_time}_connection_error_msg.txt"
    device_info = log_folder / f"{current_time}_device_info.txt"
    config = log_folder / f"{current_time}_configuration_log.txt"
    commands = log_folder / f"{current_time}_configuration_needed.txt"
    removed = log_folder / f"{current_time}_removed_info.txt"
    tag_hostname_file = log_folder / f"{current_time}_tag_hostname.txt"
    bs_hostname_file = log_folder / f"{current_time}_bs_hosname.txt"

    conn_msg_file = open(conn_msg, "w")
    device_info_file = open(device_info, "w")
    config_file = open(config, "w")
    commands_file = open(commands, "w")
    removed_file = open(removed, "w")

    for device in devices:
        if device.connection_status:
            export_device_info(device, device_info_file)  # export device info: show, status, etc
        else:
            failed_conn_count += 1
            conn_msg_file.write("-" * 80 + "\n")
            conn_msg_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")
            conn_msg_file.write(f"{device.connection_error_msg}\n")
            unavailable_device.append(f"{device.hostname} : {device.ip_address}")
            
        if settings["conf"] and device.commands:
            config_file.write("#" * 80 + "\n")
            config_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")
            config_file.write("".join(device.configuration_log))
            config_file.write("\n\n")
        elif not settings["conf"] and device.commands:
            commands_file.write(f"### {device.hostname} : {device.ip_address}\n\n")
            commands_file.write("\n".join(device.commands))
            commands_file.write("\n\n\n")
            devices_with_cfg.append(f"{device.hostname} : {device.ip_address}")

        if device.removed_info:
            removed_file.write(f"{device.hostname}\t{' '.join(device.removed_info)}\n")

        if device.unknown_mac:
            unknown_mac.extend(device.unknown_mac)

        # check if a optic bs is connectec via RRL
        for pv in device.port_bs.values():
            if not tag_hostname.get(pv["tag"]):
                tag_hostname[pv["tag"]] = device.hostname
        for mc in device.bs.values():
            bs_hostname[mc["bs_id"]] = device.hostname

    conn_msg_file.close()
    device_info_file.close()
    config_file.close()
    commands_file.close()
    removed_file.close()

    if not settings["conf"]:
        config.unlink()
    if all([dev.connection_status is True for dev in devices]):
        conn_msg.unlink()
    if not settings["conf"] and devices_with_cfg:
        print("\n" + "-" * 103 + "\n")
        print(f"devices with cfg ({len(devices_with_cfg)}):\n")
        for d in devices_with_cfg:
            print(d)
    if unknown_mac:
        print("\n" + "-" * 103 + "\n")
        print(f"devices with unknown mac ({len(unknown_mac)}):\n")
        for u in unknown_mac:
            print(u)
    if unavailable_device:
        print("\n" + "-" * 103 + "\n")
        print(f"unavailable devices ({len(unavailable_device)}):\n")
        for ud in unavailable_device:
            print(ud)

    # check if a optic bs is connectec via RRL
    print("\n" + "-" * 103 + "\n"
          "bs on multiple devices check:\n")
    with open(tag_hostname_file, "w") as thf:
        for tagk, tagv in tag_hostname.items():
            thf.write(f"{tagk} : {tagv}\n")
    with open(bs_hostname_file, "w") as bhf:
        for bsk, bsv in bs_hostname.items():
            bhf.write(f"{bsk} : {bsv}\n")
    for bsid, bshost in bs_hostname.items():
        for tagid, taghost in tag_hostname.items():
            if bsid in tagid and bshost != taghost:
                print(f"{bsid} is on devices: {bshost}, {taghost}")

    return failed_conn_count



def export_device_info(dev, export_file):
    export_file.write("#" * 80 + "\n")
    export_file.write(f"### {dev.hostname} : {dev.ip_address} ###\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.show_isis_log\n\n")
    export_file.write(dev.show_isis_log)
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.show_mac_log\n\n")
    export_file.write(dev.show_mac_log)
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.bs\n\n")
    export_file.write(pformat(dev.bs))
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.port_bs\n\n")
    export_file.write(pformat(dev.port_bs))
    export_file.write("\n\n")



#######################################################################################
# ------------------------------ get bs port -----------------------------------------#
#######################################################################################



def log_parse(dev, bs_dict, bs_dict_backup):
    version_pattern = re.compile(r"[Cc]isco (.*) \(\S+\) processor.*of memory")
    # cisco ASR-903 (RSP1) processor (revision RSP1) with 504200K/6147K bytes of memory.
    chassis_sn_pattern = re.compile(r"[Pp]rocessor board ID (\w+)")
    # Processor board ID FOX1235H1LT
    
    for line in dev.show_mac_log.splitlines():
        match = re.search(pattern, line)
        if match:
            vlan = match[1]     # 3001
            mac = match[2]      # 48fd.8e05.6fa7
            port = match[3]     # Gi0/8
            if bs_dict.get(mac):
                bs = bs_dict[mac]
            else:
                if bs_dict_backup.get(mac):
                    bs = bs_dict_backup[mac]
                else:
                    bs = mac

            if dev.bs.get(mac):
                dev.bs[mac]["vlan"].append(vlan)
            else:
                dev.bs[mac] = {"bs_id": bs,
                               "port": port,
                               "if_vlan": [],
                               "vlan": [vlan]}
                               
            if "Po" in port:
                dev.lag[port] = {"members": [], "tag": []}



def csg_arp_log_parse(dev):
    pattern = re.compile(r"Internet\s+\d+\.\d+\.\d+\.\d+\s+\d+\s+(\w{4}\.\w{4}\.\w{4})\s+ARPA\s+Vlan(\d+)")
    # Internet  10.165.161.87          11   (d849.0b95.af44)  ARPA   Vlan(1000)
    for line in dev.show_arp_log.splitlines():
        match = re.search(pattern, line)  # ip mac inf_vlan
        if match:
            mac = match[1]  # d849.0b95.af44
            inf = match[2]  # 1000 (without Vlan)
            if dev.bs.get(mac):
                dev.bs[mac]["if_vlan"].append(inf)
            else:
                print(f"{dev.hostname:39}arp_log_parse - {mac} not in MAC table")


def pagg_arp_log_parse(dev, bs_dict, bs_dict_backup):
    pattern = re.compile(r"(\w{4}\.\w{4}\.\w{4}) +Dynamic +ARPA +([-A-Za-z]+)([0-9/]+)\.(\d+)$")
    # 10.146.56.1     00:02:06   (883f.d304.e2a1)  Dynamic    ARPA  (GigabitEthernet)(0/0/0/5).(1080)
    # 10.164.24.243   00:02:11   (845b.1260.9241)  Dynamic    ARPA  (Bundle-Ether)(10).(1004)

    pattern_bvi = re.compile(r"(\w{4}\.\w{4}\.\w{4}) +Dynamic +ARPA +BVI(\d+)")
    # 10.165.192.178  00:00:48   (d849.0b8a.dcd1)  Dynamic    ARPA  BVI(1000)

    for line in dev.show_arp_log.splitlines():
        match = re.search(pattern, line)
        match_bvi = re.search(pattern_bvi, line)
        if match:
            mac = match[1]              # 883f.d304.e2a1
            port_ethernet = match[2]    # GigabitEthernet
            port_number = match[3]      # 0/0/0/5
            vlan = match[4]             # 1080
            
            if bs_dict.get(mac):
                bs = bs_dict[mac]
            else:
                if bs_dict_backup.get(mac):
                    bs = bs_dict_backup[mac]
                else:
                    bs = mac

            if port_ethernet == "Bundle-Ether":
                port_ethernet = "BE"
            elif port_ethernet == "TenGigE":
                port_ethernet = "Te"
            elif port_ethernet == "GigabitEthernet":
                port_ethernet = "Gi"
            else:
                print(f"{dev.hostname:39}pagg_arp_log_parse: Gi,Te,Be not in {port_ethernet}")

            if dev.bs.get(mac):
                dev.bs[mac]["vlan"].append(vlan)
            else:
                dev.bs[mac] = {"port": f'{port_ethernet}{port_number}',
                               "if_vlan": [],
                               "vlan": [vlan],
                               "bs_id": bs}
                               
            if port_ethernet == "BE":
                dev.lag[f"{port_ethernet}{port_number}"] = {"members": [], "tag": []}

        if match_bvi:
            mac = match_bvi[1]
            bvi = match_bvi[2]

            if bs_dict.get(mac):
                bs = bs_dict[mac]
            else:
                if bs_dict_backup.get(mac):
                    bs = bs_dict_backup[mac]
                else:
                    bs = mac

            if dev.bs.get(mac):
                dev.bs[mac]["if_vlan"].append(bvi)
            else:
                dev.bs[mac] = {"port": '',
                               "if_vlan": [bvi],
                               "bs_id": bs}


def csg_define_pagg(dev):
    pattern = re.compile(r"[0-9.]{14} ([a-z.]+-\d+-pagg-\d)")
    for line in dev.show_isis_log.splitlines():
        match = re.search(pattern, line)
        if match:
            dev.pagg = match[1]


def csg_description_parse(dev):
    pattern_port = re.compile(r"((?:Gi|Te|Po)\S+)\s+up\s+up\s*(.*)")    # (Gi0/6) up up (AK7137 BS: ALG005 AK7160)
    pattern_port_tag_bs = re.compile(r"(?:(.*)\s)?BS:\s?(.*)")          # (AK7137) BS: (ALG005 AK7160)
    pattern_inf = re.compile(r"Vl(\d+)\s+up\s+up\s*(.*)")               # Vl(1000) up up (ABIS BS: ALG005 AK7160)
    pattern_inf_tag_bs = re.compile(r"(?:.*\s)?BS:\s?(.*)")             # ABIS BS: (ALG005 AK7160)

    for line in dev.show_description_log.splitlines():
        match_port = re.search(pattern_port, line)
        match_inf = re.search(pattern_inf, line)
        if match_port:
            port = match_port[1]
            description = match_port[2]
            if not any(i in line for i in dev.description_exclude):
                if "BS:" in description:
                    match_port_tag_bs = re.search(pattern_port_tag_bs, description)
                    if match_port_tag_bs:
                        tag = match_port_tag_bs[1]
                        bs = match_port_tag_bs[2]
                        dev.port_bs[port] = {"tag": f'{tag if tag else ""}',
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": bs,
                                             "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_port_tag_bs} re match error")
                else:
                    if len(description) > 0:
                        dev.port_bs[port] = {"tag": description,
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}
                    else:
                        dev.port_bs[port] = {"tag": "",
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}
        elif match_inf:
            inf = match_inf[1]
            description = match_inf[2]
            tag = None
            if inf not in dev.exclude_inf and not any(i in line for i in dev.description_exclude):
                for m in ["ABIS", "IUB", "OAM", "S1U", "S1MME", "X2", "S1C"]:
                    if m in description:
                        tag = m
                        break
                if tag is None:
                    print(f"{dev.hostname:39}no ABIS,X2,IUB,S1MME,S1U,S1C,OAM in description interface vlan{inf}")
                if "BS:" in description:
                    match_inf_tag_bs = re.search(pattern_inf_tag_bs, description)
                    if match_inf_tag_bs:
                        bs = match_inf_tag_bs[1]
                        dev.ifvlan_bs[inf] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": bs,
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_inf_tag_bs} re match error")
                else:
                    if len(description) > 0 and tag is not None:
                        dev.ifvlan_bs[inf] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": "",
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}no description interface vlan{inf}")


def xe_description_parse(dev):
    pattern_port = re.compile(r"((?:Gi|Po)\S+)\s+up\s+up\s*(.*)")
    pattern_port_tag_bs = re.compile(r"(?:(.*)\s)?BS:\s?(.*)")
    pattern_inf = re.compile(r"BD(\d+)\s+up\s+up\s*(.*)")       # BD(1000)
    pattern_inf_tag_bs = re.compile(r"(?:.*\s)?BS:\s?(.*)")     # ABIS BS: (ALG005 AK7160)
    
    for line in dev.show_description_log.splitlines():
        match_port = re.search(pattern_port, line)
        match_inf = re.search(pattern_inf, line)
        if match_port:
            port = match_port[1]
            description = match_port[2]
            if not any(i in line for i in dev.description_exclude):
                if "BS:" in description:
                    match_port_tag_bs = re.search(pattern_port_tag_bs, description)
                    if match_port_tag_bs:
                        tag = match_port_tag_bs[1]
                        bs = match_port_tag_bs[2]
                        dev.port_bs[port] = {"tag": f'{tag if tag else ""}',
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": bs,
                                             "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_port_tag_bs} re match error")
                else:
                    if len(description) > 0:
                        dev.port_bs[port] = {"tag": description,
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}
                    else:
                        dev.port_bs[port] = {"tag": "",
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}
        elif match_inf:
            inf = match_inf[1]
            description = match_inf[2]
            tag = None
            if inf not in dev.exclude_inf and not any(i in line for i in dev.description_exclude):
                for m in ["ABIS", "IUB", "OAM", "S1U", "S1MME", "X2", "S1C"]:
                    if m in description:
                        tag = m
                        break
                if tag is None:
                    print(f"{dev.hostname:39}no ABIS,X2,IUB,S1MME,S1U,S1C,OAM in description interface vlan{inf}")
                if "BS:" in description:
                    match_inf_tag_bs = re.search(pattern_inf_tag_bs, description)
                    if match_inf_tag_bs:
                        bs = match_inf_tag_bs[1]
                        dev.ifvlan_bs[inf] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": bs,
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_inf_tag_bs} re match error")
                else:
                    if len(description) > 0 and tag is not None:
                        dev.ifvlan_bs[inf] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": "",
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}no description interface vlan{inf}")


def pagg_description_parse(dev):
    pattern = re.compile(r"((?:Gi|Te|BE)[0-9/]+)\s+up\s+up\s*(.*)$")
    # (Gi0/0/0/5)     up  up  (AU7104 BS: ZHA012)
    # Gi0/0/0/5.1000  up  up  AU7104
    pattern_tag_bs = re.compile(r"(?:(.*)\s)?BS:\s?(.*)")
    # (AU7104) BS: (ZHA012)
    pattern_bvi = re.compile(r"BV(\d+) +up +up *(.*)$")
    pattern_bvi_tag_bs = re.compile(r"(?:.*\s)?BS:\s?(.*)")

    for line in dev.show_description_log.splitlines():
        match = re.search(pattern, line)
        match_bvi = re.search(pattern_bvi, line)
        if match:
            port = match[1]
            description = match[2]
            if not any(i in line for i in dev.description_exclude):
                if "BS:" in description:
                    match_port_tag_bs = re.search(pattern_tag_bs, description)
                    if match_port_tag_bs:
                        tag = match_port_tag_bs[1]
                        bs = match_port_tag_bs[2]
                        dev.port_bs[port] = {"tag": f'{tag if tag else ""}',
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": bs,
                                             "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_port_tag_bs} re match error")
                else:
                    if len(description) > 0:
                        dev.port_bs[port] = {"tag": description,
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}
                    else:
                        dev.port_bs[port] = {"tag": "",
                                             "bs": [],
                                             "new_bs_description": "",
                                             "current_bs_description": "",
                                             "bs_on_description": []}

        elif match_bvi:
            bvi = match_bvi[1]
            description = match_bvi[2]
            tag = None
            if bvi not in dev.exclude_inf and not any(i in line for i in dev.description_exclude):
                for m in ["ABIS", "IUB", "OAM", "S1U", "S1MME", "X2", "S1C"]:
                    if m in description:
                        tag = m
                        break
                if tag is None:
                    print(f"{dev.hostname:39}no ABIS,X2,IUB,S1MME,S1U,S1C,OAM in description interface vlan{bvi}")
                if "BS:" in description:
                    match_bvi_tag_bs = re.search(pattern_bvi_tag_bs, description)
                    if match_bvi_tag_bs:
                        bs = match_bvi_tag_bs[1]
                        dev.ifvlan_bs[bvi] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": bs,
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}{match_bvi_tag_bs} re match error")
                else:
                    if len(description) > 0 and tag is not None:
                        dev.ifvlan_bs[bvi] = {"tag": tag,
                                              "bs": [],
                                              "new_bs_description": "",
                                              "current_bs_description": "",
                                              "bs_on_description": []}
                    else:
                        print(f"{dev.hostname:39}no description interface vlan{bvi}")



#######################################################################################
# ------------------------------              ----------------------------------------#
#######################################################################################

def connect_device(my_username, my_password, dev_queue, bs_dict, bs_dict_backup, settings):
    while True:
        dev = dev_queue.get()
        i = 0
        while True:
            try:
                # print(f"{device.hostname:23}{device.ip_address:16}")
                dev.ssh_conn = ConnectHandler(device_type=dev.os_type, ip=dev.ip_address,
                                              username=my_username, password=my_password)
                dev.show_commands()
                define_inf_exclude(dev)
                dev.parse(dev, bs_dict, bs_dict_backup)
                dev.lag_member_tag(dev)
                dev.delete_info(dev)
                description_bs_parse(dev)
                dev.define_port_bs(dev)
                shorten_bs(dev)
                dev.make_config(dev)
                configure(dev, settings)
                dev.ssh_conn.disconnect()
                dev_queue.task_done()
                break

            except NetMikoTimeoutException as err_msg:
                dev.connection_status = False
                dev.connection_error_msg = str(err_msg)
                print(f"{dev.hostname:23}{dev.ip_address:16}timeout")
                dev_queue.task_done()
                break
                 
            except SSHException:
                i += 1
                dev.reset()
                print(f"{dev.hostname:23}{dev.ip_address:16}SSHException occurred \t i={i}")
                time.sleep(5)

            except Exception as err_msg:
                if i == 2:  # tries
                    dev.connection_status = False
                    dev.connection_error_msg = str(err_msg)
                    print(f"{dev.hostname:23}{dev.ip_address:16}{'BREAK connection failed':20} i={i}")
                    dev_queue.task_done()
                    break
                else:
                    i += 1
                    dev.reset()
                    print(f"{dev.hostname:23}{dev.ip_address:16}ERROR connection failed \t i={i}")
                    time.sleep(5)


#######################################################################################
# ------------------------------ test        -----------------------------------------#
#######################################################################################

def test_connect_dev(dev, settings):
    if settings["os_type"] == "cisco_ios":
        with open("test_arp.txt", "r") as arp:
            dev.show_arp_log = arp.read()
        with open("test_descrip.txt", "r") as descr:
            dev.show_description_log = descr.read()
        with open("test_isis_pagg.txt", "r") as isis_host:
            dev.show_isis_log = isis_host.read()
        with open("test_isis_neig.txt", "r") as isis_neigh:
            dev.show_isis_neighbors_log = isis_neigh.read()
        with open("test_mac.txt", "r") as mac:
            dev.show_mac_log = mac.read()
        with open("test_tengig.txt", "r") as ten:
            dev.show_tengig_bw_log = ten.read()

    elif settings["os_type"] == "cisco_xr":
        with open("test_pagg_arp.txt", "r") as arp:
            dev.show_arp_log = arp.read()
        with open("test_pagg_description.txt", "r") as descr:
            dev.show_description_log = descr.read()


def test_connect(dev_queue, settings, bs_dict, bs_dict_backup):
    dev = dev_queue.get()
    test_connect_dev(dev, settings)
    define_inf_exclude(dev)
    dev.parse(dev, bs_dict, bs_dict_backup)
    dev.lag_member_tag(dev)
    dev.delete_info(dev)
    description_bs_parse(dev)
    dev.define_port_bs(dev)
    shorten_bs(dev)
    dev.make_config(dev)
    configure(dev, settings)
    dev_queue.task_done()


def test_connect2(my_username, my_password, dev_queue, bs_dict, settings):
    dev = dev_queue.get()
    dev.ssh_conn = ConnectHandler(device_type=dev.os_type, ip=dev.ip_address,
                                  username=my_username, password=my_password)
    dev.show_commands()
    define_inf_exclude(dev)
    dev.parse(dev, bs_dict)
    dev.lag_member_tag(dev)
    dev.delete_info(dev)
    description_bs_parse(dev)
    dev.define_port_bs(dev)
    shorten_bs(dev)
    dev.make_config(dev)
    configure(dev, settings)
    dev.ssh_conn.disconnect()
    dev_queue.task_done()


#######################################################################################
# ------------------------------ main part -------------------------------------------#
#######################################################################################

start_time = datetime.now()
current_date = start_time.strftime("%Y.%m.%d")
current_time = start_time.strftime("%H.%M")

log_folder = Path(f"{Path.cwd()}/logs/{current_date}/")  # current dir / logs / date /
log_folder.mkdir(exist_ok=True)

q = queue.Queue()

settings = get_arguments(argv)
username, password = get_user_pw()
devices = get_device_info("devices.yaml", settings)
mac_bs, mac_bs_backup = load_excel(current_date, current_time)  # 04bd.70dc.a7ee : TA7175, информация от МТС

total_devices = len(devices)

print(
    "\n"
    f"Total devices: {total_devices}\n"
    "-------------------------------------------------------------------------------------------------------\n"
    "hostname               ip address      comment\n"
    "---------------------- --------------- ----------------------------------------------------------------\n"
)

for i in range(settings["maxth"]):
    thread = Thread(target=connect_device, args=(username, password, q, mac_bs, mac_bs_backup, settings))
    # thread = Thread(target=test_connect, args=(q, settings, mac_bs, mac_bs_backup))
    # thread = Thread(target=test_connect2, args=(username, password, q, mac_bs, argv_dict))
    thread.setDaemon(True)
    thread.start()

for device in devices:
    q.put(device)

q.join()

failed_connection_count = write_logs(devices, current_time, log_folder, settings)
duration = datetime.now() - start_time
duration_time = timedelta(seconds=duration.seconds)

print("\n"
      "-------------------------------------------------------------------------------------------------------\n"
      f"failed connection:.....{failed_connection_count}\n"
      f"elapsed time:..........{duration_time}\n"
      "-------------------------------------------------------------------------------------------------------")
