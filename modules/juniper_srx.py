import re
# from misc import get_timezone
from .misc import netmask_to_cidr


class ToJuniperSRX:
    def __init__(self, securityZone, hostname, timezone, dns, dnat_list, ntpserver, snat, static_route, firewall_address, addrgrp, custom_services, interfaces, firewall_policy):
        self.securityZone = securityZone
        self.hostname = hostname
        self.timezone = timezone
        self.dns = dns
        self.ntpserver = ntpserver
        self.snat = snat
        self.dnat_list = dnat_list
        self.static_route = static_route
        self.firewall_address = firewall_address
        self.addrgrp = addrgrp
        self.custom_services = custom_services
        self.interfaces = interfaces
        self.firewall_policy = firewall_policy

    def get_hostname(self, line):
        hostname = line.split("set hostname")[1].split('\n')[0].split('"')[1]
        return hostname

    def get_timezone(self, line):
        timezone = line.split("set timezone")[1].split('\n')[0].strip()
        # timezone = get_timezone(timezone)
        return timezone

    def get_ntp(self, line):
        ntp = line.replace('\n', '').split('set server')[1:]
        ntp = [n.strip(' ').split(' ')[0] for n in ntp]
        ntp = [n.strip('"') for n in ntp]
        return ntp

    def get_dns(self, line):
        dns = line.split('\n')
        dns = list(filter(None, dns))[1:]
        dns = [d.strip(' ').split(' ')[2] for d in dns]
        return dns

    def get_firewall_address(self, line, srx):
        line = line.split('\n')
        firewall_addr = {
            "name": "",
            "ip": ""
        }
        for l in line:
            if "edit" in l:
                firewall_addr['name'] = l.split(
                    ' ')[-1].replace('"', '')
            elif "set subnet" in l:
                subnet = netmask_to_cidr(l.split(' ')[-1])
                ip = l.split(' ')[-2]
                firewall_addr['ip'] = f"{ip}/{subnet}"
            elif "next" in l and firewall_addr['name'] != "" and firewall_addr['ip'] != "":
                srx.firewall_address.append(firewall_addr)
                firewall_addr = {
                    "name": "",
                    "ip": ""
                }

    def get_static_routing(self, line):
        static_route = []
        line = list(line.split('\n'))
        line.pop(0)
        line = [l.strip() for l in line]
        data = {
            "ip": "",
            "nexthop": "",
            "device": ""
        }
        for l in line:
            if re.match(r'set dst ', l):
                ip = l.split(' ')[2]
                subnet = l.split(' ')[3]
                data["ip"] = f"{ip}/{netmask_to_cidr(subnet)}"
                # print(data['ip'])
            if re.match(r'set dstaddr', l):
                addr = l.split(' ')[2]
                data["ip"] = addr
            if 'set gateway' in l:
                data["nexthop"] = l.split('gateway')[1].lstrip()
                # print(data['nexthop'])
            if 'device' in l:
                data["device"] = l.split('device')[1].strip().replace('"', '')

            if 'next' in line and data['ip'] != '' and data['nexthop'] != '':
                static_route.append(data)
                data = {
                    "ip": "",
                    "nexthop": "",
                    "device": ""
                }
        # for d in static_route:
        #     print(d)
        return static_route

    def get_addrgrp(self, line, srx):
        line = line.split('\n')
        addrgrp = {
            "name": "",
            "member": []
        }
        for l in line:
            # l = l.split(' ')
            if 'edit' in l:
                addrgrp['name'] = l.split(' ')[-1].replace('"', '')
            elif 'set member' in l:
                members = list(l.strip().replace(
                    '"', '').split(' ')[2:])
                addrgrp['member'] = members
            elif 'next' in l and addrgrp['member'] != [] and addrgrp['name'] != "":
                srx.addrgrp.append(addrgrp)
                addrgrp = {
                    "name": "",
                    "member": []
                }

    def get_custom_services(self, line, srx):
        line = line.split('\n')
        service_custom = {
            "name": "",
            "protocol": "",
            "port": ""
        }
        for l in line:
            l = l.strip()
            if "edit" in l:
                service_custom['name'] = l.split(
                    ' ')[-1].replace('"', '')
            elif 'portrange' in l:
                service_custom['protocol'] = l.split(' ')[
                    1].split('-')[0]
                service_custom['port'] = l.split(' ')[-1]
            elif 'next' in l and service_custom['name'] != "" and service_custom['port'] != "" and service_custom['protocol'] != "":
                srx.custom_services.append(service_custom)
                service_custom = {
                    "name": "",
                    "protocol": "",
                    "port": ""
                }

    def get_snat(self, line, srx):
        snat_dict = {
            "name": "",
            "startip": "",
            "endip": ""
        }
        l = line.split('\n')
        for d in l:
            if "edit" in d:
                snat_dict["name"] = d.split(' ')[-1].replace('"', '')
            elif "startip" in d:
                snat_dict["startip"] = d.split(' ')[-1].strip()
            elif "endip" in d:
                snat_dict['endip'] = d.split(' ')[-1].strip()
            elif "next" in d:
                srx.snat.append(snat_dict)
                snat_dict = {
                    "name": "",
                    "startip": "",
                    "endip": ""
                }

    def get_firewall_policy(self, line, srx, ctr_policies):
        ctr_policies += 1
        line = line.split('\n')
        policy = {
            "name": "",
            "srcintf": [],
            "dstintf": [],
            "srcaddr": [],
            "dstaddr": [],
            "action": "",
            "app": []
        }
        for l in line:
            l = l.strip()
            if 'set name' in l:
                policy['name'] = l.split(' ')[-1].replace('"', '')
            elif 'set srcintf' in l:
                srcintf_list = l.split('srcintf')[-1].split(' ')
                srcintf_list.pop(0)
                srcintf_list = [d.strip().replace('"', '')
                                for d in srcintf_list]
                # print(srcintf_list)
                policy['srcintf'] = ([d for d in srcintf_list])
            elif 'set dstintf' in l:
                dstintf_list = l.split('dstintf')[-1].split(' ')
                dstintf_list.pop(0)
                dstintf_list = [d.strip().replace('"', '')
                                for d in dstintf_list]
                # print(srcintf_list)
                policy['dstintf'] = ([d for d in dstintf_list])
            elif 'set srcaddr' in l:
                srcaddr_list = l.split('srcaddr')[-1].split(' ')
                srcaddr_list.pop(0)
                srcaddr_list = [d.strip().replace('"', '')
                                for d in srcaddr_list]
                policy['srcaddr'] = ([d for d in srcaddr_list])
            elif 'set dstaddr' in l:
                dstaddr_list = l.split('dstaddr')[-1].split(' ')
                dstaddr_list.pop(0)
                # print([d.strip().replace('"', '') for d in dstaddr_list])
                dstaddr_list = [d.strip().replace('"', '')
                                for d in dstaddr_list]
                # print(srcintf_list)
                policy['dstaddr'] = ([d for d in dstaddr_list])
                # print(policy['dstaddr'])
            elif 'set action' in l:
                policy['action'] = l.split(' ')[-1].replace('"', '')
            elif 'set service' in l:
                app = (l.split("service")[-1])
                app_list = [a for a in app.split('"') if a != '' and a != ' ']
                policy['app'] = app_list
            elif 'next' in l:
                if policy['name'] == '':
                    policy['name'] = f"Policy-{ctr_policies}"
                srx.firewall_policy.append(policy)
                policy = {
                    "name": "",
                    "srcintf": [],
                    "dstintf": [],
                    "srcaddr": [],
                    "dstaddr": [],
                    "action": "",
                    "app": []
                }

    def dnat(self, line):
        line = line.split('\n')
        dnat_p = {
            "name": "",
            "extip": "",
            "extintf": "",
            "mappedip": ""
        }
        for l in line:
            if "edit" in l:
                name = l.strip().split(' ')[-1]
                dnat_p["name"] = name
            elif "set extip" in l:
                extip = l.strip().split(' ')[-1]
                dnat_p["extip"] = extip
            elif "set extinf" in l:
                extintf = l.strip().split(' ')[-1]
                dnat_p["extintf"] = extintf
            elif "set mappedip" in l:
                mappedip = l.strip().split(' ')[-1]
                dnat_p["mappedip"] = mappedip
            elif "next" in l:
                self.dnat_list.append(dnat_p)
                dnat_p = {
                    "name": "",
                    "extip": "",
                    "extintf": "",
                    "mappedip": ""
                }

    def firewall_policy(self, original):
        return original
