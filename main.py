import yaml
import time
import queue
import re
from threading import Thread
from pprint import pformat
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
        self.pid_count = "ERROR"

        self.chassis = {"model": "-", "sn": "-"}
        self.pid = []   # [{}{}{}]

    def show_commands(self):
        self.show_version = self.ssh_conn.send_command(r"show version")
        self.show_inventory = self.ssh_conn.send_command(r"show inventory")

    def reset(self):
        self.connection_status = True
        self.connection_error_msg = None
        self.show_version = None
        self.show_inventory = None
        self.chassis = {"model": "-", "sn": "-"}
        self.pid = []


class CiscoXR(CiscoIOS):
    def __init__(self, ip, host):
        CiscoIOS.__init__(self, ip, host)
        self.os_type = "cisco_xr"

    def show_commands(self):
        self.show_version = self.ssh_conn.send_command(r"show version brief")
        self.show_inventory = self.ssh_conn.send_command(r"admin show inventory")


class CiscoXE(CiscoIOS):
    def __init__(self, ip, host):
        CiscoIOS.__init__(self, ip, host)
        self.os_type = "cisco_xe"


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
        elif arg in ("xr", "xe", "hua", "mx"):
            settings["os_type"] = arg
  
    print("\n"
          f"max threads:...................{settings['maxth']}\n"
          )
    return settings


def get_user_pw():
    with open("psw.yaml") as file:
        user_psw = yaml.load(file, yaml.SafeLoader)

    return user_psw[0], user_psw[1]


def get_device_info(csv_file):
    devs = []
    with open(csv_file, "r") as file:
        for line in file:
            if "#" not in line and len(line) > 5:
                hostname, ip_address, ios = line.strip().split(",")

                if ios in ["ios", "cisco_ios"]:
                    dev = CiscoIOS(ip=ip_address, host=hostname)
                    devs.append(dev)
                elif ios in ["ios xr", "cisco_xr", "xr"]:
                    dev = CiscoXR(ip=ip_address, host=hostname)
                    devs.append(dev)
                elif ios in ["ios xe", "cisco_xe", "xe"]:
                    dev = CiscoXE(ip=ip_address, host=hostname)
                    devs.append(dev)
                else:
                    print(f"wrong ios: {ios}")

    return devs


def write_logs(devices, current_time, log_folder, settings):
    failed_conn_count = 0
    unavailable_device = []

    conn_msg = log_folder / f"{current_time}_connection_error_msg.txt"
    device_info = log_folder / f"{current_time}_device_info.txt"
    cisco_model = log_folder / f"{current_time}_model.csv"
    inventory = log_folder / f"{current_time}_inventory.csv"
    pid_count_info = log_folder / f"{current_time}_pid_count_info.txt"

    conn_msg_file = open(conn_msg, "w")
    device_info_file = open(device_info, "w")
    model_file = open(cisco_model, "w")
    inventory_file = open(inventory, "w")
    pid_count_info_file = open(pid_count_info, "w")

    for device in devices:
        if device.connection_status:
            export_device_info(device, device_info_file)  # export device info: show, status, etc
            model_file.write(f"{device.hostname},{device.ip_address},{device.chassis['model']},{device.chassis['sn']}\n")
            pid_count_info_file.write(f"{device.hostname},{device.ip_address},{device.pid_count}\n")
            for p in device.pid:
                inventory_file.write(f"{device.hostname},{device.ip_address},{p['pid']},{p['sn']},{p['descr']}\n")
        else:
            failed_conn_count += 1
            conn_msg_file.write("-" * 80 + "\n")
            conn_msg_file.write(f"### {device.hostname} : {device.ip_address} ###\n\n")
            conn_msg_file.write(f"{device.connection_error_msg}\n")
            unavailable_device.append(f"{device.hostname},{device.ip_address},{device.os_type}")
            
    conn_msg_file.close()
    device_info_file.close()
    model_file.close()
    inventory_file.close()
    pid_count_info_file.close()

    if unavailable_device:
        print("\n" + "-" * 103 + "\n")
        print(f"unavailable devices ({len(unavailable_device)}):\n")
        for ud in unavailable_device:
            print(ud)

    else:
        conn_msg.unlink()

    return failed_conn_count


def export_device_info(dev, export_file):
    export_file.write("#" * 80 + "\n")
    export_file.write(f"### {dev.hostname} : {dev.ip_address} ###\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.show_version\n\n")
    export_file.write(dev.show_version)
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.show_inventory\n\n")
    export_file.write(dev.show_inventory)
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.chassis\n\n")
    export_file.write(pformat(dev.chassis))
    export_file.write("\n\n")

    export_file.write("-" * 80 + "\n")
    export_file.write("device.pid\n\n")
    export_file.write(pformat(dev.pid))
    export_file.write("\n\n")


#######################################################################################
# ------------------------------ get bs port -----------------------------------------#
#######################################################################################


def log_parse(dev):
    version_pattern = re.compile(r"[Cc]isco (\S+) \(.* memory")
    # cisco ASR-903 (RSP1) processor (revision RSP1) with 504200K/6147K bytes of memory.
    chassis_sn_pattern = re.compile(r"[Pp]rocessor board ID (\w+)")
    # Processor board ID FOX1235H1LT
    
    if "IOS XR" in dev.show_version:
        if "ASR9K" in dev.show_version:
            chassis = dev.ssh_conn.send_command("admin show inventory chassis")
            pattern = re.compile(r"PID: (\S+)\s+.*SN: (\S+)")
            for line in chassis.splitlines():
                match = re.search(pattern, line)
                if match:
                    dev.chassis["model"] = match[1]
                    dev.chassis["sn"] = match[2]

        else:
            log1 = dev.ssh_conn.send_command("admin", expect_string="#")
            chassis = dev.ssh_conn.send_command("show inventory chassis")
            pattern = re.compile(r"PID: \S+\s+.*SN: (\S+)")

            for line in dev.show_version.splitlines():
                match = re.search(version_pattern, line)
                if match:
                    dev.chassis["model"] = match[1]

            for line in chassis.splitlines():
                match = re.search(pattern, line)
                if match:
                    dev.chassis["sn"] = match[1]

            log2 = dev.ssh_conn.send_command("exit", expect_string="#")
            
    else:
        for line in dev.show_version.splitlines():
            match_version = re.search(version_pattern, line)
            match_chassis_sn = re.search(chassis_sn_pattern, line)

            if match_version:
                cisco_model = match_version[1]          # ASR-903
                dev.chassis["model"] = cisco_model

            elif match_chassis_sn:
                chassis_sn = match_chassis_sn[1]        # FOX1235H1LT
                dev.chassis["sn"] = chassis_sn


def pid_parse(dev):
    descr_pattern = re.compile(r'NAME.*DESCR:\s*"(.*)"')
    # NAME: "GigabitEthernet 0/5", DESCR: "1000BASE-LX SFP"
    pid_sn_pattern = re.compile(r"PID:(.*),\s*VID.*,\s*SN:(.*)")
    # PID: GLC-LH-SM         , VID: A  , SN: FNS17041MJY

    result = {
        "pid": "-",
        "descr": "-",
        "sn": "-"}


    if "IOS XR" in dev.show_version:
        log1 = dev.ssh_conn.send_command("admin", expect_string="#")
        dev.show_inventory = dev.ssh_conn.send_command("show inventory")       
        log2 = dev.ssh_conn.send_command("exit", expect_string="#")

    for line in dev.show_inventory.splitlines():
        match_descr = re.search(descr_pattern, line)
        match_pid_sn = re.search(pid_sn_pattern, line)

        if match_descr:
            description = match_descr[1].strip()
            description_new = description.replace(",", ".")
            result["descr"] = description_new

        elif match_pid_sn:
            result["pid"] = match_pid_sn[1].strip()
            result["sn"] = match_pid_sn[2].strip()

            dev.pid.append(result)
            result = {
                "pid": "-",
                "descr": "-",
                "sn": "-"}


def check_pid_match(dev):

    count = dev.show_inventory.count("PID")
    pid_len = len(dev.pid)

    if count != pid_len:
        print(f"{dev.hostname:23}{dev.ip_address:16}ERROR: PID and PID_SN do not match")
    else:
        dev.pid_count = "OK"


#######################################################################################
# ------------------------------              ----------------------------------------#
#######################################################################################

def connect_device(my_username, my_password, dev_queue, settings):
    while True:
        dev = dev_queue.get()
        i = 0
        while True:
            try:
                try:
                    dev.ssh_conn = ConnectHandler(device_type=settings['os_type'], ip=dev.ip_address, username=my_username, password=my_password)
                except:
                    dev.ssh_conn = ConnectHandler(device_type="cisco_ios_telnet", ip=dev.ip_address, username=my_username, password=my_password)
                    print(f"{dev.hostname:23}{dev.ip_address:16}access via telnet")

                dev.show_commands()
                log_parse(dev)
                pid_parse(dev)
                check_pid_match(dev)
                dev.ssh_conn.disconnect()
                dev_queue.task_done()
                break
                
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
                    time.sleep(5)


#######################################################################################
# ------------------------------ test        -----------------------------------------#
#######################################################################################

def test_connect_dev(dev, settings):
    if settings["os_type"] == "cisco_ios":
        with open("test_version.txt", "r") as vers:
            dev.show_version = vers.read()
        with open("test_inventory.txt", "r") as invent:
            dev.show_inventory = invent.read()

    elif settings["os_type"] == "cisco_xr":
        with open("test_version.txt", "r") as vers:
            dev.show_version = vers.read()
        with open("test_inventory.txt", "r") as invent:
            dev.show_inventory = invent.read()


def test_connect(dev_queue, settings):
    dev = dev_queue.get()
    test_connect_dev(dev, settings)
    log_parse(dev)
    pid_parse(dev)
    dev_queue.task_done()


def test_connect2(my_username, my_password, dev_queue, settings):
    dev = dev_queue.get()
    dev.ssh_conn = ConnectHandler(device_type=dev.os_type, ip=dev.ip_address,
                                  username=my_username, password=my_password)
    dev.show_commands()
    log_parse(dev)
    pid_parse(dev)
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
devices = get_device_info("devices.csv")

total_devices = len(devices)

print(
    "\n"
    f"Total devices: {total_devices}\n"
    "-------------------------------------------------------------------------------------------------------\n"
    "hostname               ip address      comment\n"
    "---------------------- --------------- ----------------------------------------------------------------\n"
)

for i in range(settings["maxth"]):
    thread = Thread(target=connect_device, args=(username, password, q, settings))
    # thread = Thread(target=test_connect, args=(q, settings))
    # thread = Thread(target=test_connect2, args=(username, password, q, settings))
    thread.daemon = True
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
