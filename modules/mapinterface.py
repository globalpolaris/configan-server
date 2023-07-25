import re
from .misc import *


def map_srx(interfaces, config):
    with open(config, 'r') as f:
        # print(f.readlines())
        for _, line in enumerate(f):
            line = line.lstrip()
            # print(line)
            for v in interfaces:
                for item in interfaces[v]:
                    if f"vlan-id {item['vlan']}" in line:
                        next(f)
                        ip_fam = next(f).lstrip().split(' ')[1].replace(
                            ';', '')
                        _, cidr = get_network_address(ip_fam.rstrip())
                        item["cidr"] = str(cidr)


def map_vlan(fgt, line):
    vlan = line.split(' ')[4]
    if vlan not in fgt.vlan:
        fgt.vlan[vlan] = {
            "addr": "",
            "cidr": "",
            "vrname": ""
        }

    if "family inet address" in line:
        fgt.vlan[vlan]["addr"] = line.split(' ')[-1].rstrip()
        _, fgt.vlan[vlan]["cidr"] = get_network_address(
            fgt.vlan[vlan]["addr"])
    # return vlan


def map_static_route_vlan(vlan_list, staticroute_list):
    # for i, obj in vlan_list.items():
    #     print(i, obj["addr"])
    # for i in staticroute_list:
    #     print(i)
    # print(staticroute_list)
    for s in staticroute_list:
        for vlan, obj in vlan_list.items():
            # print(s["nextHop"], obj["cidr"])
            is_inside_network = check_ip_range(s["nextHop"], obj["cidr"])
            if is_inside_network:
                s["vlanid"] = vlan
                s["vrname"] = obj["vrname"]
                # print(s, obj)
                break

    # return data
