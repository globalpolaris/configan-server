from misc import cidr_to_netmask, get_ip_range
import json

dst_port = {
  "afs": 1483,
  "bgp": 179,
  "biff": 512,
  "bootpc": 68,
  "bootps": 67,
  "cmd": 514,
  "cvspserver": 2401,
  "dhcp": 67,
  "domain": 53,
  "eklogin": 2105,
  "ekshell": 2106,
  "excc": 512,
  "finger": 79,
  "ftp": 21,
  "ftp-data": 20,
  "http": 80,
  "https": 443,
  "ident": 113,
  "imap": 143,
  "kerberos-sec": 88,
  "klogin": 543,
  "kpasswd": 761,
  "krb-prop": 754,
  "krbupdate": 760,
  "kshell": 544,
  "ldap": 389,
  "ldp": 646,
  "login": 513,
  "mobileip-agent": 434,
  "mobilip-mn": 435,
  "msdp": 639,
  "netbios-dgm": 138,
  "netbios-ns": 137,
  "netbios-ssn": 139,
  "nfsd": 2049,
  "nntp": 119,
  "ntalk": 518,
  "ntp": 123,
  "pop3": 110,
  "pptp": 1723,
  "printer": 515,
  "radacct": 1813,
  "radius": 1812,
  "rip": 520,
  "rkinit": 2108,
  "smtp": 25,
  "snmp": 161,
  "snmp-trap": 162,
  "snpp": 444,
  "socks": 1080,
  "ssh": 22,
  "sunrpc": 111,
  "syslog": 514,
  "tacacs": 49,
  "tacacs-ds": 65,
  "talk": 517,
  "telnet": 23,
  "tftp": 69,
  "timed": 525,
  "who": 513,
  "xdmcp": 177
}



class ToFortigate:

    def __init__(self, router_policy, dnat_pool, dnat_rule_set, policy_statement, routing_instance, security_zone, dns_list, ntp, hostname, fw_ippool, fw_address,
                 interfaces, static_route, vlan, fw_policy, custom_services, security_policy, addr_group):
        self.router_policy = router_policy
        self.dnat_pool = dnat_pool
        self.dnat_rule_set = dnat_rule_set
        self.routing_instance = routing_instance
        self.policy_statement = policy_statement
        self.security_zone = security_zone
        self.dns_list = dns_list
        self.ntp_list = ntp
        self.hostname = hostname
        self.fw_ippool = fw_ippool
        self.fw_address = fw_address
        self.static_route = static_route
        self.interfaces = interfaces
        self.vlan = vlan
        self.fw_policy = fw_policy
        self.custom_services = custom_services
        self.security_policy = security_policy
        self.addr_group = addr_group
    # Convert NAT

    def get_dnat_pool(self, line):
        pool_name = line.split(' ')[5]
        ip = line.split(' ')[-1].strip()
        if ip.split('/')[-1] == "32":
            ip = ip.split('/')[0]
        else:
            ip = get_ip_range(ip)
        self.dnat_pool[pool_name] = {
            "mapped_ip": ip
        }

    def get_router_policy(self, line):
        global dst_port
        name = line.split(' ')[5].strip()
        if name not in self.router_policy:
            self.router_policy[name] = {
                "protocol": "",
                "dstport": "",
                "routing_instance": "",
                "gateway": "",
                "dstintf": ""
            }

        if "from protocol" in line:
            self.router_policy[name]["protocol"] = line.split(' ')[-1].strip()
        elif "from destination-port" in line:
            apps = line.split(' ')[-1].strip()
            self.router_policy[name]["dstport"] = dst_port[apps]
        elif "then routing-instance" in line:
            self.router_policy[name]["routing_instance"] = line.split(
                ' ')[-1].strip()
            gateway = self.static_route

    def get_dnat_rule(self, line):
        rule_set = line.split(' ')[5]
        dst_addr = ""
        dst_pool = ""
        if rule_set not in self.dnat_rule_set:
            self.dnat_rule_set[rule_set] = {
                "from_zone": "",
                "rules": {}
            }
            if "from zone" in line:
                zone = line.split(' ')[-1].strip()
                self.dnat_rule_set[rule_set]["from_zone"] = zone
        elif rule_set in self.dnat_rule_set:
            rule_name = line.split(' ')[7]
            if rule_name not in self.dnat_rule_set[rule_set]["rules"]:
                self.dnat_rule_set[rule_set]["rules"][rule_name] = {
                    "dst_addr": "",
                    "dst_pool": "",
                    "mapped_ip": ""
                }
                if "match destination-address" in line:
                    dst_addr = line.split(' ')[-1].strip()
                    if dst_addr.split('/')[-1] == '32':
                        self.dnat_rule_set[rule_set]["rules"][rule_name]["dst_addr"] = dst_addr.split(
                            '/')[0]
                    else:
                        self.dnat_rule_set[rule_set]["rules"][rule_name]["dst_addr"] = get_ip_range(
                            dst_addr)
            elif rule_name in self.dnat_rule_set[rule_set]["rules"]:
                if "then destination-nat pool" in line:
                    dst_pool = line.split(' ')[-1].strip()
                    self.dnat_rule_set[rule_set]["rules"][rule_name]["dst_pool"] = dst_pool

    def map_dnat_rule_to_pool(self):
        for set_rule, set_info in self.dnat_rule_set.items():
            for rule, rule_info in set_info["rules"].items():
                for pool, pool_info in self.dnat_pool.items():
                    if rule_info['dst_pool'] == pool:
                        rule_info["mapped_ip"] = pool_info["mapped_ip"]

    def dns(self, line):
        self.dns_list.append(
            line.split('set system name-server')[1].replace('\n', '').strip())

    def map_routing_instance_forwarding(self, line):
        name = line.split(' ')[2].strip()
        if name not in self.routing_instance:
            self.routing_instance[name] = {}
        if "routing-instances" in line and "routing-options static route" in line:
            ip = line.split(' ')[6].strip()
            next_hop = line.split(' ')[-1].strip()
            self.routing_instance[name]["ip"] = ip
            self.routing_instance[name]["next_hop"] = next_hop
            # print(name, self.routing_instance[name])
        if "routing-instances" in line and "routing-options instance-import" in line:
            # print(line)
            statement = line.split(' ')[-1].strip()
            self.routing_instance[name]["statement"] = statement

    def get_policy_statement(self, line):
        # print(line)
        name = line.split(' ')[3]
        # print(name)
        if name not in self.policy_statement:
            self.policy_statement[name] = {
                "term": "", "src_device": [], "src_intf": []}
        if "term" in line:
            term = line.split(' ')[5]
            if term not in self.policy_statement[name]["term"] and term.lower() != "others":
                self.policy_statement[name]["term"] = (term)
        if "from instance" in line:
            # print("adding dst device")
            self.policy_statement[name]["src_device"].append(line.split(
                ' ')[-1].replace('\n', ''))
        if "from interface" in line:
            # print("adding dst intf")
            self.policy_statement[name]["src_intf"].append(line.split(
                ' ')[-1].replace('\n', ''))
        if "then" in line:
            term = line.split(' ')[5]
            if term == self.policy_statement[name]["term"]:
                self.policy_statement[name]["action"] = line.split(
                    ' ')[-1].strip()

    def map_routing_instance_to_policy(self):
        for ri, ri_item in self.routing_instance.items():
            for ps, ps_item in self.policy_statement.items():
                if ri_item["statement"] == ps:
                    ps_item["routing_instance"] = ri

    def addr_obj_group(self, line):
        address_book = {"objectName": "", "ip": "", "subnet": ""}
        address_book["objectName"] = line.strip(' ').split(' ')[7]
        ip_sub = line.strip(' ').split(' ')[8].strip('\n')
        network, netmask = cidr_to_netmask(ip_sub)
        # print(network, netmask)
        address_book["ip"] = network
        address_book["subnet"] = netmask
        return address_book

    def map_security_zone(self, line):
        zone_name = line.split('security-zone')[1].strip().split(' ')[0]
        if zone_name not in self.security_zone:
            self.security_zone[zone_name] = {"interfaces_vlan": []}
        # else:
        interface_vlan = line.split('interfaces ')[1].split(' ')[
            0].split('.')[1]
        self.security_zone[zone_name]["interfaces_vlan"].append(
            interface_vlan)

    def get_custom_services(self, line):

        line = line.split(' ')
        # print(line)
        name = line[3]
        if name not in self.custom_services:
            if "application-set" in line:
                self.custom_services[name] = {
                    "application": []
                }
            else:
                self.custom_services[name] = {
                    "protocol": "",
                    "port": ""
                }
        if "protocol" in line and "application-set" not in line:
            self.custom_services[name]["protocol"] = line[-1].rstrip()
        elif "destination-port" in line and "application-set" not in line:
            self.custom_services[name]["port"] = line[-1].rstrip()
        else:
            if "application" in line:
                self.custom_services[name]["application"].append(
                    line[-1].rstrip())

    def snat(self, line):
        # print(line)
        ippool = {"poolName": "", "startIp": "", "endIp": ""}
        line = line.split(' ')
        ln = len(line)
        if ln == 8:
            ippool["poolName"] = line[5]
            ippool["startIp"] = line[7].split('/')[0]
            ippool["endIp"] = ippool["startIp"]
        elif ln == 10:
            ippool["poolName"] = line[5]
            ippool["startIp"] = line[7].split('/')[0]
            ippool["endIp"] = line[9].split('/')[0]
        return ippool

    def routing_interface(self, line, vlan_dict):
        # print(vlan_dict)
        l = line.split(' ')
        # print(line)
        vrname = l[2]
        data = {
            "vrname": vrname,
            "vlan": l[-1].strip('\n').split('.')[-1],
            "cidr": ""
        }
        for i in vlan_dict:
            if i == data["vlan"]:
                vlan_dict[i]["vrname"] = vrname

        return data

    def routing_options(self, line):
        data = {
            "ip": line.split(' ')[6],
            "nextHop":
            line.lstrip().split('next-hop')[-1].strip('\n').lstrip(),
            "vlanid": "",
            "type": "vlan"
        }
        return data

    def get_addr_group(self, line):
        line = line.rstrip().split(' ')
        name = line[7]
        if name not in self.addr_group:
            self.addr_group[name] = {
                "members": []
            }
        self.addr_group[name]["members"].append(f'"{line[-1].rstrip()}"')

    def get_firewall_policy(self, line):
        line = line.split(' ')
        name = line[8]
        if name not in self.security_policy:
            self.security_policy[name] = {
                "src_intf": "",
                "dst_intf": "",
                "src_addr": "",
                "dst_addr": "",
                "application": [],
                "action": "",
                "schedule": "always",
                "nat": "enable",
            }
        if "from-zone" in line:
            self.security_policy[name]["src_intf"] = line[4]
            self.security_policy[name]["dst_intf"] = line[6]
        if "source-address" in line:
            self.security_policy[name]["src_addr"] = line[-1].rstrip()
        if "destination-address" in line:
            self.security_policy[name]["dst_addr"] = line[-1].rstrip()
        if "then" in line:
            self.security_policy[name]["action"] = line[-1].rstrip()
        if "application" in line:
            self.security_policy[name]["application"].append(
                line[-1].rstrip())
        # return line

    def ntp(self, line):
        self.ntp_list.append(
            line.split('set system ntp server')[1].replace('\n', '').strip())
