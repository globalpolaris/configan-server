import json
import uuid
from modules.fortigate import ToFortigate
from modules.juniper_srx import ToJuniperSRX
import re
from modules import misc
from modules import mapinterface
from .transform_json import transform_json_srx, transform_json_fgt
from pathlib import Path


def to_srx(file, output_file):
    srx = ToJuniperSRX("", "", [], [], [], [], [], [], [], [], [], [], [])
    ctr_policies = 0
    with open(file) as f:
        for line in f.read().split('end\n'):
            if 'config system global' in line:
                if "set hostname" in line:
                    srx.hostname = srx.get_hostname(line)
                if "set timezone" in line:
                    srx.timezone = srx.get_timezone(line)
            elif 'config system dns' in line:
                srx.dns = srx.get_dns(line)

            elif 'config system ntp' in line:
                srx.ntpserver = srx.get_ntp(
                    "".join(line.split('ntpserver')[1]))
            elif 'config firewall ippool' in line:
                srx.get_snat(line, srx)

            elif 'config router static' in line:
                srx.static_route = srx.get_static_routing(line)
                # print(srx.static_route)

            elif 'config firewall address' in line:
                srx.get_firewall_address(line, srx)
                # print(firewall_addr)

            elif 'config firewall addrgrp' in line:
                srx.get_addrgrp(line, srx)

            elif 'config firewall service custom' in line:
                srx.get_custom_services(line, srx)

            elif 'config system interface' in line:
                line = line.split('\n')
                typeintf = ""
                interface = {
                    "name": "",
                    "type": "",
                    "interface": "",
                    "ip": "",
                    "vlanid": ""
                }
                for l in line:
                    l = l.strip()
                    if "edit" in l:
                        interface['name'] = l.split(' ')[-1].replace('"', '')
                    elif "set ip" in l:
                        ip = l.split(' ')[-2]
                        subnet = l.split(' ')[-1]
                        interface['ip'] = f'{ip}/{misc.netmask_to_cidr(subnet)}'
                    elif "set vlanid" in l:
                        interface['vlanid'] = l.split(' ')[-1]
                        interface['type'] = "vlan"
                    elif "set type" in l and interface['type'] == "":
                        typeintf = l.split(' ')[-1]
                        interface['type'] = typeintf
                    elif "set interface" in l:
                        interface['interface'] = l.split(
                            ' ')[-1].replace('"', '')
                    elif "next" in l:
                        if typeintf != "physical" and typeintf != "tunnel":
                            srx.interfaces.append(interface)
                        interface = {
                            "name": "",
                            "type": "",
                            "interface": "",
                            "ip": "",
                            "vlanid": ""
                        }
            elif 'config firewall vip' in line:
                srx.dnat(line)
            elif 'config firewall policy' in line:
                srx.get_firewall_policy(line, srx, ctr_policies)
            # elif 'config firewall address':
            #     l = line.split('\n')
            #     print(l)
            # for l in line.split('\n'):
            #     print(l)
    transform_json_srx(srx, output_file)

    # output_srx(output_file, srx)


def to_fgt(file, timezone,  output_file):
    fgt = ToFortigate({}, {}, {}, {}, {}, {}, [], [], [], [],
                      [], [], [], {}, [], {}, {}, {})
    static_route = {}

    route_data = []
    # print(fgt.custom_services)
    # mapinterface.map_vlan(fgt.vlan, file)
    with open(file) as f:
        for _, line in enumerate(f):
            if 'set system name-server' in line:
                fgt.dns(line)
            elif re.match("set interfaces .+ unit .+", line):
                mapinterface.map_vlan(fgt, line)
            elif 'set system ntp server' in line:
                fgt.ntp(line)
            elif 'set security nat source pool' in line:
                # print(line)
                fgt.fw_ippool.append(fgt.snat(line))
            elif re.match("set security zones security-zone .+ address-book address .+", line):
                fgt.fw_address.append(fgt.addr_obj_group(line))
            elif re.match("set security zones security-zone .+ interfaces", line):
                fgt.map_security_zone(line)

            elif re.match("set routing-instances .+ instance-type forwarding", line):
                name = line.split(' ')[2].strip()
                static_route[name] = {"type": "forwarding"}
            elif re.match(
                    "set routing-instances .+ instance-type virtual-router",
                    line):
                # Add Virtual Routing to static_route dictionary
                vrname = line.split(' ')[2]
                static_route[vrname] = []
            elif re.match("set routing-instances .+ interface .+", line):
                data = fgt.routing_interface(line, fgt.vlan)
                # print(data)
                route_data.append(data)
            elif re.match("set routing-instances .+ routing-options instance-import", line):
                fgt.map_routing_instance_forwarding(line)
            elif re.match(
                    "set routing-instances .+ routing-options static route",
                    line):
                name = line.split(' ')[2]
                # print(type(static_route[name]))
                if type(static_route[name]) == dict:
                    fgt.map_routing_instance_forwarding(line)
                    # fgt.static_route.append(data)

                else:
                    data = fgt.routing_options(line)
                    fgt.static_route.append(data)

            elif re.match("set applications application", line):
                fgt.get_custom_services(line)

            elif re.match("set policy-options policy-statement .+ term .+", line):
                fgt.get_policy_statement(line)

            elif re.match("set security policies from-zone .+ to-zone .+ policy .+", line):
                fgt.get_firewall_policy(line)

            elif re.match('set security zones security-zone .+ address-book address-set .+ address', line):
                fgt.get_addr_group(line)

            elif re.match('set security nat destination pool', line):
                fgt.get_dnat_pool(line)

            elif re.match('set security nat destination rule-set', line):
                fgt.get_dnat_rule(line)

            elif re.match('set firewall family inet filter .+ term .+', line):
                fgt.get_router_policy(line)
    for item in route_data:
        static_route[item["vrname"]].append(item)
    fgt.interfaces = static_route
    mapinterface.map_static_route_vlan(fgt.vlan, fgt.static_route)
    fgt.map_routing_instance_to_policy()
    fgt.map_dnat_rule_to_pool()
    for pr, item in fgt.router_policy.items():
        gateway = fgt.routing_instance[item["routing_instance"]]["next_hop"]
        fgt.router_policy[pr]["gateway"] = gateway
        for vlan, data_v in fgt.vlan.items():
            cidr = data_v["cidr"]
            if misc.check_ip_range(gateway, cidr):
                item["dstintf"] = f'{data_v["vrname"]}-{vlan}'
    transform_json_fgt(fgt, output_file, timezone)


def process(destination, timezone, filename):

    id = uuid.uuid4()
    if destination.lower() == 'fortigate':
        filename = str(Path(f"./config_files/{filename}").resolve())
        dst_file = str(Path(f"./config_files/json/fgt_{id}.json").resolve())
        to_fgt(filename, timezone, dst_file)
        f = open(dst_file)
        data = json.load(f)
        return {
            "data": data,
            "filename": filename
        }
    if destination.lower() == 'junipersrx':
        filename = str(Path(f"./config_files/{filename}").resolve())
        print(filename)
        dst_file = str(Path(f"./config_files/json/srx_{id}.json").resolve())
        to_srx(filename, dst_file)
        f = open(dst_file)
        data = json.load(f)
        return {
            "data": data,
            "filename": filename
        }
