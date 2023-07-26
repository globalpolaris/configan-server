from modules import misc
from modules import mapinterface


def output_srx(file, srx):
    print("writing to: ", file)
    with open(file, 'w+') as output:
        output.write(f"set host-name {srx['hostname']}\n")
        output.write(
            f"set system time-zone {srx['timezone'] if srx['timezone'] else '[Timezone]'}\n")
        # output.write("\nDNS Server\n")
        for item in srx['dns']:
            output.write(f"set system name-server {item}\n")
        output.write("\nNTP Server\n")
        for item in srx['ntpserver']:
            output.write(f"set system ntp server {item}\n")

        # output.write('\nInterfaces\n')
        for item in srx['interfaces']:
            if item['type'] == 'vlan' and item['ip'] != "":
                output.write(
                    f'set interfaces {item["interface"]} unit {item["vlanid"]} vlan-id {item["vlanid"]}\n')
                output.write(
                    f'set interfaces {item["interface"]} unit {item["vlanid"]} family inet address {item["ip"]}\n')

        # output.write("\nSNAT Pool\n")
        for item in srx["snat"]:
            output.write(
                f'set security nat source pool {item["name"]} address {item["startip"]}/32 to {item["endip"]}/32\n'
            )
        # print("Writing DNAT...")
        output.write("\nDNAT\n")
        for item in srx["dnat"]:
            output.write(
                f'set security nat destination pool {item["name"]} {item["extip"]}/32\n')
        # output.write('\nStatic Routing\n')
        for item in srx["static_route"]:
            output.write(
                f'set routing-instances {item["interface"] if "interface" in item else "[interface]"} routing-options static route {item["ip"]} next-hop {item["nexthop"]}\n')
        print("Writing Firewall address...")
        output.write('\nFirewall Address\n')
        for item in srx["firewall_address"]:
            print(item)
            output.write(
                f'set security zones security-zone {item["zone"] if "zone" in item else "[Security Zone Address Book]"} address-book address {item["name"]} {item["ip"]}\n')

        # output.write('\nAddress Group\n')
        for item in srx["addrgrp"]:
            # print("addrgrp:",item)
            for member in item["member"]:
                # print(item["zone"] if item["zone"] else "Zone")
                output.write(
                    f'set security zones security-zone {item["zone"] if "zone" in item else "[Zone]"} address-book address-set {item["name"]} address {member}\n')

        # output.write('\nCustom Services\n')
        for item in srx["custom_services"]:
            output.write(
                f'set applications application {item["name"]} protocol {item["protocol"]}\n')
            output.write(
                f'set applications application {item["name"]} destination-port {item["port"]}\n')

        # output.write('\nFirewall Policies\n')
        for item in srx["firewall_policy"]:
            for src in item["srcaddr"]:
                output.write(
                    f'set security policies from-zone {item["from-zone"] if "from-zone" in item else "[From-Zone]"} to-zone {item["to-zone"] if "to-zone" in item else "[To-Zone]"} policy {item["name"]} match source-address {src}\n')
            for dst in item["dstaddr"]:
                output.write(
                    f'set security policies from-zone {item["from-zone"] if "from-zone" in item else "[From-Zone]"} to-zone {item["to-zone"] if "to-zone" in item else "[To-Zone]"} policy {item["name"]} match destination-address {dst}\n')
            for app in item["app"]:
                output.write(
                    f'set security policies from-zone {item["from-zone"] if "from-zone" in item else "[From-Zone]"} to-zone {item["to-zone"] if "to-zone" in item else "[To-Zone]"} policy {item["name"]} match application {app.lower()}\n')
            output.write(
                f'set security policies from-zone {item["from-zone"] if "from-zone" in item else "[From-Zone]"} to-zone {item["to-zone"] if "to-zone" in item else "[To-Zone]"} policy {item["name"]} then {"permit" if item["srcaddr"] == "accept" else "deny"}\n')


def output_fgt(file, fgt):
    # print(json.dumps(fgt, indent=4))
    with open(file, 'w+') as output:
        # Write DNS to Fortigate
        for idx, d in enumerate(fgt["dns_list"]):
            if idx == 0:
                output.write("config system dns\n")
            if idx == 0:
                output.write(f"    set primary {d}\n")
            elif idx == 1:
                output.write(f"    set secondary {d}\n")
        output.write("end\n")

        # Write NTP Server Fortigate

        output.write("\nconfig system ntp\n")
        output.write("    set ntpsync enable\n")
        output.write("    set type custom\n")
        output.write("    config ntpserver\n")

        for idx, x in enumerate(fgt["ntp_list"]):
            output.write(f'        edit {idx+1}\n')
            output.write(f'            set server {x}\n')
            output.write("        next\n")
        output.write("    end\n")
        output.write("end\n")

        # Write SNAT to Fortigate
        output.write("\nconfig firewall ippool\n")
        for snat in fgt["fw_ippool"]:
            output.write(f'    edit "{snat["poolName"]}"\n')
            output.write(f'        set startip {snat["startIp"]}\n')
            output.write(f'        set endip {snat["endIp"]}\n')
            output.write(f'    next\n')
        output.write('end\n')

        # Write Firewall Address
        output.write('\nconfig firewall address\n')
        for addr in fgt["fw_address"]:
            output.write(f'    edit "{addr["objectName"]}"\n')
            output.write(f'        set type ipmask\n')
            output.write(f'        set subnet {addr["ip"]} {addr["subnet"]}\n')
            output.write('    next\n')
        output.write('end\n')

        # Config Firewall Address Group
        output.write('\nconfig firewall addrgrp\n')
        for addrgrp, v in fgt["addr_group"].items():
            output.write(f'    edit {addrgrp}\n')
            output.write(
                f'        set member {" ".join(member for member in v["members"])}\n')
            # output.write(f'        set allow-routing enable\n')
            output.write('    next\n')
        output.write('end\n')
        # Config interface
        for vlan, item in fgt["vlan"].items():
            if item["vrname"] == "":
                item["vrname"] = f"VLAN-{vlan}"
            else:
                item["vrname"] = f"{item['vrname']}-{vlan}"
        lag_interface = "LAG-Interface"
        output.write('\nconfig system interface\n')
        output.write(f'    edit "LAG-Interface"\n')
        output.write(f'        set vdom "root"\n')
        output.write(f'        set type aggregate\n')
        if "lag-member" in fgt:
            output.write(
                f'        set member {", ".join(member for member in fgt["lag-member"])}\n')
        output.write(f'    next\n')

        # Create VLAN
        # mapinterface.map_srx(fgt["interfaces"], file)
        # mapinterface.map_vlan(fgt.interfaces, fgt.static_route)
        ctr = 1
        for vlan, item in fgt["vlan"].items():

            output.write(f'    edit "{item["vrname"]}"\n')
            output.write(f'        set vdom "root"\n')
            _, netmask = misc.cidr_to_netmask(item["addr"])
            output.write(
                f'        set ip {item["addr"].split("/")[0]} {netmask}\n')
            output.write(f'        set interface "{lag_interface}"\n')
            output.write(f'        set vlanid {vlan}\n')
            output.write(f'    next\n')
        output.write(f'end\n')

        # Config Static Route
        output.write('\nconfig router static\n')
        ctr = 1
        for i, sr in enumerate(fgt["static_route"]):
            if sr['vlanid'] != '' and sr['vrname'] != '':
                ip, netmask = misc.cidr_to_netmask(sr['ip'])
                output.write(f'    edit {ctr}\n')
                output.write(f'        set dst {ip} {netmask}\n')
                output.write(f'        set gateway {sr["nextHop"]}\n')
                output.write(
                    f'        set device "{sr["vrname"]}-{sr["vlanid"]}"\n')
                output.write(f'    next\n')
                ctr += 1
        output.write('end\n')

        # Config Custom Services
        output.write('\nconfig firewall service custom\n')
        for key in fgt["custom_services"]:
            if "application" not in fgt["custom_services"][key]:
                # print(fgt.custom_services[key]["protocol"])
                output.write(f'    edit "{key}"\n')
                if fgt["custom_services"][key]["protocol"].lower() == "udp":
                    output.write(
                        f'        set udp-portrange {fgt["custom_services"][key]["port"]}\n')
                    output.write(f'    next\n')

                elif fgt["custom_services"][key]["protocol"].lower() == "tcp":
                    output.write(
                        f'        set tcp-portrange {fgt["custom_services"][key]["port"]}\n')
                    output.write(f'    next\n')
        output.write('end\n')

        # Config Firewall VIP
        output.write('config firewall vip\n')
        for _, set_info in fgt["dnat_rule_set"].items():
            for rule, rule_info in set_info['rules'].items():
                output.write(f'    edit {rule}\n')
                output.write(
                    f'        set extip {rule_info["dst_addr"]}\n')
                output.write(f'        set extintf any\n')
                output.write(
                    f'        set mappedip {rule_info["mapped_ip"]}\n')
                output.write('    next\n')
        output.write('end\n')

        # Config Firewall Policy
        output.write('\nconfig firewall policy\n')
        ctr = 0
        # print(fgt["security_zone"])
        for policy, v in fgt["security_policy"].items():
            src_intf = fgt["security_zone"][v["src_intf"]]["interfaces_vlan"]
            dst_intf = fgt["security_zone"][v["dst_intf"]]["interfaces_vlan"]
            # intf_list = list(
            #     f'{fgt["vlan"][src]["vrname"]}-{fgt["security_zone"][v["src_intf"]]}' for src in src_intf)
            # print(list(fgt["vlan"][src]["vrname"] for src in src_intf))
            # print(s for s in src_intf)
            # print(fgt["security_zone"][v["src_intf"]])
            # print(intf_list)
            # for s in src_intf:
            complete_src_intf = []
            complete_dst_intf = []
            for s in src_intf:
                complete_src_intf.append(fgt["vlan"][s]["vrname"])
            for s in dst_intf:
                complete_dst_intf.append(fgt["vlan"][s]["vrname"])
            ctr += 1
            srcintf_f = ", ".join(['"{}"'.format(item)
                                   for item in complete_src_intf])
            dstintf_f = ", ".join(['"{}"'.format(item)
                                   for item in complete_dst_intf])
            print(v['application'])
            output.write(f'    edit {ctr}\n')
            output.write(f'        set name "{policy}"\n')
            output.write(
                f'        set srcintf {""""all" """ if v["dst_intf"] == "any" else srcintf_f}\n')
            output.write(
                f'        set dstintf {""""all" """ if v["dst_intf"] == "any" else dstintf_f}\n')
            output.write(
                f'        set srcaddr {""""all" """ if v["src_addr"] == "any" else """"{}" """.format(v["src_addr"])}\n')
            output.write(
                f'        set dstaddr {""""all" """ if v["dst_addr"] == "any" else """"{}" """.format(v["dst_addr"])}\n')
            output.write(
                f'        set action {""""accept" """ if v["action"].lower() == "permit" else "deny"}\n')
            output.write(f'        set service "ALL"\n')
            output.write(f'        set schedule {v["schedule"]}\n')
            output.write(f'    next\n')
        output.write(f'end\n')

        # Output Policy Statement
        print(fgt)
        output.write("config router policy\n")
        ctr = 1
        for key, item in fgt["router_policy"].items():
            if "routing_instance" in item:
                output.write(f"    edit {ctr}\n")
                output.write(f'        set protocol 6\n')
                output.write(f'        set start-port {item["dstport"]}\n')
                output.write(f'        set end-port {item["dstport"]}\n')
                output.write(f'        set action permit\n')
                output.write(f'        set output-device {item["dstintf"]}\n')
                output.write(f'        set gateway {item["gateway"]}\n')
                output.write('    next\n')
                ctr += 1
        output.write("end\n")
