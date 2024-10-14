from psutil import virtual_memory, cpu_count
from subprocess import check_output
from requests import get, post
import platform as p

app_version = 0.1

#! Get data
api = get('https://api.ipapi.is').json()
ram = virtual_memory()


#! Set network (IP-based) data
ip = api['ip']
abuser_score = api['company']['abuser_score'].split('(')[1].split(')')[0]
company = api['asn']['org']
is_tor = api['is_tor']
is_proxy = api['is_proxy']
registrar = api['rir']
is_vpn = False
vpn_provider = []

if abuser_score == "High":
    networkSuspicious = True
elif abuser_score == "Elevated":
    networkSuspicious = True
elif abuser_score == "Low":
    networkSuspicious = False
elif abuser_score == "Very Low":
    networkSuspicious = False
else:
    networkSuspicious: False

if "M247" in company:
    is_vpn = True
    vpn_provider = ["Proton", "Kaspersky"]
    networkSuspicious = True

elif "Latitude.sh" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky"]
    networkSuspicious = True

elif "Private Customer" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky"]
    networkSuspicious = True

elif "Anchorfree" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky", "Hotspot Shield"]
    networkSuspicious = True

elif "TR1 Net" in company:
    is_vpn = True
    vpn_provider =  ["Kaspersky"]
    networkSuspicious = True

elif "Leaseweb" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky"]
    networkSuspicious = True

elif "WorldStream" in company:
    is_vpn = True
    vpn_provider = ["Proton"]
    networkSuspicious = True

elif "20 Point Networks" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky"]
    networkSuspicious = True
    
elif "24SHELLS" in company:
    is_vpn = True
    vpn_provider = ["Kaspersky"]
    networkSuspicious = True

#! Set network (Geolocation) data
country = api['location']['country']
city = api['location']['city']
latitude = api['location']['latitude']
longitude = api['location']['longitude']
zip_code = api['location']['zip']
timezone = api['location']['timezone']

#! Set hardware data
try:
    uuid = check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
except:
    uuid = "None found"
ram_GiB = ram.total / (1024**3)
ram_GB = ram.total / (1000**3)
cpu_threads = cpu_count()

#! Set software (operating system) data
arch = p.architecture()[0]
release = p.release()
version = p.version()
edition = p.win32_edition()
pc_name = p.node()
operating_system = p.system()

#! Export session
data = {
    "network":{
        "ip":ip,
        "is_tor":is_tor,
        "is_vpn":is_vpn,
        "company":company,
        "suspicious":networkSuspicious,
        "vpn_provider":vpn_provider
    },
    "geolocation":{
        "country":country
    },
    "hardware":{
        "uuid":uuid,
        "threads":cpu_threads,
        "ram_GiB":ram_GiB,
        "ram_GB":ram_GB
    },
    "software":{
        "operating_system":operating_system,
        "pc_name":pc_name,
        "release":release,
        "version":version,
        "edition":edition,
        "arch":arch,
        "app_version":app_version
    }
}

webhook_url = "YOUR_WEBHOOK_URL"
response = post(webhook_url, json=data)