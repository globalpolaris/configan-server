import json


def transform_json_srx(srx, output_file):
    data = {
        "securityZone": srx.securityZone,
        "hostname": srx.hostname,
        "timezone": srx.timezone,
        "dns": srx.dns,
        "ntpserver": srx.ntpserver,
        "snat": srx.snat,
        "dnat": srx.dnat_list,
        "static_route": srx.static_route,
        "firewall_address": srx.firewall_address,
        "addrgrp": srx.addrgrp,
        "custom_services": srx.custom_services,
        "interfaces": srx.interfaces,
        "firewall_policy": srx.firewall_policy,
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)


def transform_json_fgt(fgt, output_file, timezone):
    data = {
        "router_policy": fgt.router_policy,
        "timezone": timezone,
        "dnat_pool": fgt.dnat_pool,
        "dnat_rule_set": fgt.dnat_rule_set,
        "routing_instance": fgt.routing_instance,
        "policy_statement": fgt.policy_statement,
        "security_zone": fgt.security_zone,
        "ntp_list": fgt.ntp_list,
        "dns_list": fgt.dns_list,
        "hostname": fgt.hostname,
        "fw_ippool": fgt.fw_ippool,
        "fw_address": fgt.fw_address,
        "static_route": fgt.static_route,
        "interfaces": fgt.interfaces,
        "vlan": fgt.vlan,
        "fw_policy": fgt.fw_policy,
        "custom_services": fgt.custom_services,
        "security_policy": fgt.security_policy,
        "addr_group": fgt.addr_group,
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=4)
    # output_fgt("./result/toFgtRes.txt", data)
