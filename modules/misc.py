from netaddr import IPAddress, IPNetwork
from timezone import timezone_dict
import requests
import json
import os
from dotenv import load_dotenv
from ipaddress import IPv4Network, ip_address, ip_network

load_dotenv()

# data = {'code': 0, 'message': 'ok', 'data': [{'TimeZone': {'IsInside': 'false', 'AskGeoId': 19854, 'MinDistanceKm': 13.89608, 'TimeZoneId': 'Pacific/Kwajalein', 'ShortName': 'MHT', 'CurrentOffsetMs': 43200000, 'WindowsStandardName': 'Fiji Standard Time', 'InDstNow': 'false'}}]}


def get_ip_range(ip):
    ip_list = [str(ip) for ip in IPNetwork(ip)]
    return f'{ip_list[0]}-{ip_list[-1]}'


def netmask_to_cidr(netmask):
    if len(netmask) > 2:
        # print(IPAddress(netmask).netmask_bits())
        return IPAddress(netmask).netmask_bits()
    else:
        return netmask


def get_network_address(ipaddress):
    network_addr = IPv4Network(ipaddress, strict=False).network_address
    subnet = ipaddress.split('/')[1]
    cidr = f"{network_addr}/{subnet}"
    return network_addr, cidr


def check_ip_range(ipaddr, cidr):
    # print(ipaddr, cidr)
    if ip_address(ipaddr) in ip_network(cidr):
        return True
    return False


def cidr_to_netmask(cidr):
    return str(IPNetwork(cidr).network), str(IPNetwork(cidr).netmask)


# def get_timezone(code):
#     """WARNING: DO NOT USE THE API CALL FOR DEVELOPMENT PURPOSE"""

#     zone = timezone_dict[code].split(', ')
#     if len(zone) > 1:
#         tz = 0
#         print("Multiple time zone possibility detected")
#         print("Select the city you want to use as the Time Zone (Default: 1):")
#         for i, z in enumerate(zone):
#             print(f"{i+1}. {z}")
#         tz = int(input(">> "))
#         zone = zone[tz-1]

# API_URL_GET_COORDINATES = f"https://nominatim.openstreetmap.org/search?q={zone}&format=geocodejson"
# r = requests.get(API_URL_GET_COORDINATES)
# data_coordinates = json.loads(r.text)
# if len(data_coordinates["features"]) == 0:
#      print("Could not set Time Zone, please set it manually!")
# coordinates = data_coordinates["features"][0]["geometry"]["coordinates"]
# long = coordinates[1]
# lat = coordinates[0]
# API_URL_GET_TIMEZONE = f'https://api.askgeo.com/v1/{os.environ["ACC_ID"]}/{os.environ["API_KEY"]}/query.json?databases=TimeZone&points={long}%2C{lat}'
# r = requests.get(API_URL_GET_TIMEZONE)
# data_timezone = json.loads(r.text)
# return data_timezone['data'][0]['TimeZone']['TimeZoneId']
# return "Asia/Jakarta"
