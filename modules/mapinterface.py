import re
import misc


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
                        _, cidr = misc.get_network_address(ip_fam.rstrip())
                        item["cidr"] = str(cidr)

    # print(vlan)


# def map_vlan(vlan_dict, file):
#     with open(file, 'r') as f:
#         for _, line in enumerate(f):
#             line = line.strip()
#             # print(re.search('vlanid', line))
#             if re.match('vlan-id', line):
#                 data = {"vlan": "", "addr": "", "cidr": "", "vrname": ""}
#                 vlan = line.split(' ')[1].split(';')[0]
#                 data["vlan"] = vlan
#                 while 'address' not in line:
#                     line = next(f)
#                 addr = line.strip().split('address')[-1].strip().split(';')[0]
#                 data["addr"] = addr
#                 _, data["cidr"] = misc.get_network_address(addr)
#                 if len(vlan_dict) == 0:
#                     vlan_dict.append(data)
#                 else:
#                     index = -1
#                     for i, obj in enumerate(vlan_dict):
#                         if obj["vlan"] == data["vlan"]:
#                             index = i
#                             break
#                     if index == -1:
#                         vlan_dict.append(data)

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
        _, fgt.vlan[vlan]["cidr"] = misc.get_network_address(
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
            is_inside_network = misc.check_ip_range(s["nextHop"], obj["cidr"])
            if is_inside_network:
                s["vlanid"] = vlan
                s["vrname"] = obj["vrname"]
                # print(s, obj)
                break

    # return data
