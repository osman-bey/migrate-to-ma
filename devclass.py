from netmiko import ConnectHandler


#######################################################################################
# ------------------------------ classes part ----------------------------------------#
#######################################################################################


class NetworkDevice:
    def __init__(self, ip="", host=""):
        self.ip_address = ip
        self.hostname = host
        self.os_type = None

        self.conf_logs = []
        self.fconnect = False       # false - connection is successful
        self.fconnect_msg = None
        self.ssh_conn = None

        self.config = []
        self.ping_ma_status = True          # false - ping is failed
        self.arp_ma = []        # abis + iub + ...
        self.arp_abis = []  # abis arp
        self.arp_iub = []
        self.arp_oam = []
        self.arp_s1u = []
        self.arp_s1mme = []
        self.arp_oam = []
        self.ping_ma_log = []
        self.ping_abis_log = []
        self.ping_iub_log = []
        self.ping_oam_log = []
        self.ping_s1u_log = []
        self.ping_s1mme_log = []
        self.ping_oam_log = []

    def connect(self, myusername, mypassword):
        self.ssh_conn = ConnectHandler(device_type=self.os_type,
                                       ip=self.ip_address,
                                       username=myusername,
                                       password=mypassword)

    def disconnect(self):
        self.ssh_conn.disconnect()

    def configure(self, cmd):
        self.conf_logs.append(self.ssh_conn.send_config_set(cmd))


class NetworkDeviceIOS(NetworkDevice):

    def __init__(self, ip="", host=""):
        NetworkDevice.__init__(self, ip, host)
        self.os_type = "cisco_ios"

    def commit(self):
        self.conf_logs.append(self.ssh_conn.send_command('write memory'))

    def get_abis(self):
        return self.ssh_conn.send_command(r'show running-config vrf ABIS | format')

    def get_iub(self):
        return self.ssh_conn.send_command(r'show running-config vrf IUB | format')

    def get_oam(self):
        return self.ssh_conn.send_command(r'show running-config vrf OAM | format')

    def get_s1u(self):
        return self.ssh_conn.send_command(r'show running-config vrf S1U | format')

    def get_s1mme(self):
        return self.ssh_conn.send_command(r'show running-config vrf S1MME | format')

    def get_x2(self):
        return self.ssh_conn.send_command(r'show running-config vrf X2 | format')

    def show_arp_abis(self):
        return self.ssh_conn.send_command(r'show ip arp vrf ABIS | include Internet')

    def show_arp_iub(self):
        return self.ssh_conn.send_command(r'show ip arp vrf IUB | include Internet')

    def show_arp_oam(self):
        return self.ssh_conn.send_command(r'show ip arp vrf OAM | include Internet')

    def show_arp_s1u(self):
        return self.ssh_conn.send_command(r'show ip arp vrf S1U | include Internet')

    def show_arp_s1mme(self):
        return self.ssh_conn.send_command(r'show ip arp vrf S1MME | include Internet')

    def show_arp_x2(self):
        return self.ssh_conn.send_command(r'show ip arp vrf X2 | include Internet')

    def ping_ma(self, arp):
        return self.ssh_conn.send_command('ping vrf MA {}'.format(arp))
