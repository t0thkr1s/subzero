import argparse
import csv
import json
import os
from concurrent.futures import ThreadPoolExecutor

import requests
from rich.console import Console

banner = '''
            __                  
  ___ __ __/ /  ___ ___ _______ 
 (_-</ // / _ \/_ // -_) __/ _ \\
/___/\_,_/_.__//__/\__/_/  \___/     v1.0
'''

shodan_api_key = ""
whoisxmlapi_api_key = ""
certspotter_api_key = ""
dnsdb_api_key = ""
virustotal_api_key = ""
recondev_api_key = ""
passivetotal_api_key = ""
passivetotal_api_secret = ""
censys_api_id = ""
censys_api_secret = ""
facebook_access_token = ""
binaryedge_api_key = ""
spyse_api_key = ""

domain = ""
subdomains = []

console = Console()
success = "[bold white][[/bold white][bold green] ✓ [/bold green][bold white]][/bold white] "
info = "[bold white][[/bold white][bold yellow] ‣ [/bold yellow][bold white]][/bold white] "
fail = "[bold white][[/bold white][bold red] × [/bold red][bold white]][/bold white] "


def certspotter():
    console.print(info + "Gathering data from [i]Cert Spotter[/i]…")
    headers = {"Authorization": f"Bearer {certspotter_api_key}"}
    response = requests.get(f"https://api.certspotter.com/v1/issuances?domain={domain}&expand=dns_names",
                            headers=headers, stream=True)
    data = json.loads(response.text)
    for dns_names in data:
        for dns_name in dns_names["dns_names"]:
            if not dns_name.startswith('*') and not subdomains.__contains__(dns_name):
                subdomains.append(dns_name)


def hackertarget():
    console.print(info + "Gathering data from [i]Hacker Target[/i]…")
    response = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", stream=True)
    data = response.text
    lines = data.split("\n")
    for line in lines:
        sub = line.split(",")[0]
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def shodan():
    console.print(info + "Gathering data from [i]Shodan[/i]…")
    response = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={shodan_api_key}", stream=True)
    data = json.loads(response.text)
    for sub in data["subdomains"]:
        if not subdomains.__contains__(sub + "." + domain):
            subdomains.append(sub + "." + domain)


def omnisint():
    console.print(info + "Gathering data from [i]Omnisint[/i]…")
    response = requests.get(f"https://sonar.omnisint.io/subdomains/{domain}", stream=True)
    data = json.loads(response.text)
    for sub in data:
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def dns_bufferover():
    console.print(info + "Gathering data from [i]DNS Bufferover[/i]…")
    response = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}", stream=True)
    data = json.loads(response.text)
    for line in data["FDNS_A"]:
        sub = line.split(",")[1]
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def tls_bufferover():
    console.print(info + "Gathering data from [i]TLS Bufferover[/i]…")
    response = requests.get(f"https://tls.bufferover.run/dns?q=.{domain}", stream=True)
    data = json.loads(response.text)
    for line in data["Results"]:
        sub = line.split(",")[2]
        if not sub.startswith('*') and not subdomains.__contains__(sub):
            subdomains.append(sub)


def sublist3r():
    console.print(info + "Gathering data from [i]Sublist3r[/i]…")
    response = requests.get(f"https://api.sublist3r.com/search.php?domain={domain}", stream=True)
    data = json.loads(response.text)
    for sub in data:
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def threatcrowd():
    console.print(info + "Gathering data from [i]Threat Crowd[/i]…")
    response = requests.get(f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}", stream=True)
    data = json.loads(response.text)
    for sub in data["subdomains"]:
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def threatminer():
    console.print(info + "Gathering data from [i]Threat Miner[/i]…")
    response = requests.get(f"https://api.threatminer.org/v2/domain.php?q={domain}&rt=5", stream=True)
    data = json.loads(response.text)
    for sub in data["results"]:
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def virustotal():
    console.print(info + "Gathering data from [i]VirusTotal[/i]…")
    headers = {"x-apikey": virustotal_api_key}
    response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains",
                            headers=headers, stream=True)
    data = json.loads(response.text)
    for sub in data["data"]:
        if not subdomains.__contains__(sub["id"]):
            subdomains.append(sub["id"])


def securitytrails():
    console.print(info + "Gathering data from [i]SecurityTrails[/i]…")
    headers = {"apikey": "ITTUAQ0A0v4yzSbClTTySceSjPbwswsC"}
    response = requests.get(f"https://api.securitytrails.com/v1/domain/{domain}/subdomains",
                            headers=headers, stream=True)
    data = json.loads(response.text)
    for sub in data["subdomains"]:
        if not subdomains.__contains__(sub + "." + domain):
            subdomains.append(sub + "." + domain)


def alienvault():
    console.print(info + "Gathering data from [i]AlienVault[/i]…")
    response = requests.get(f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns", stream=True)
    data = json.loads(response.text)
    for sub in data["passive_dns"]:
        if not subdomains.__contains__(sub["hostname"]):
            subdomains.append(sub["hostname"])


def urlscan():
    console.print(info + "Gathering data from [i]Urlscan[/i]…")
    response = requests.get(f"https://urlscan.io/api/v1/search/?q=domain:{domain}", stream=True)
    data = json.loads(response.text)
    for res in data["results"]:
        if not subdomains.__contains__(res["page"]["domain"]):
            subdomains.append(res["page"]["domain"])


def crt():
    console.print(info + "Gathering data from [i]Crt.sh[/i]…")
    response = requests.get(f"https://crt.sh/?q={domain}&output=json", stream=True)
    data = json.loads(response.text)
    for res in data:
        for sub in res["name_value"].split("\n"):
            if not sub.startswith('*') and not subdomains.__contains__(sub):
                subdomains.append(sub)


def anubis():
    console.print(info + "Gathering data from [i]Anubis[/i]…")
    response = requests.get(f"https://jldc.me/anubis/subdomains/{domain}", stream=True)
    data = json.loads(response.text)
    for sub in data:
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def dnsdb():
    console.print(info + "Gathering data from [i]DNSdb[/i]…")
    headers = {"Accept": "application/json", "Content-Type": "application/json", "X-API-Key": dnsdb_api_key}
    response = requests.get(f"https://api.dnsdb.info/lookup/rrset/name/*.{domain}?limit=1000000000",
                            headers=headers, stream=True)
    for line in response.text.split("\n"):
        if line == "":
            continue
        sub = json.loads(line)["rrname"]
        sub = sub.rstrip(".")
        if "_" not in sub and not subdomains.__contains__(sub):
            subdomains.append(sub)


def recondev():
    console.print(info + "Gathering data from [i]Recon.dev[/i]…")
    response = requests.get(f"https://recon.dev/api/search?key={recondev_api_key}&domain={domain}", stream=True)
    data = json.loads(response.text)
    for res in data:
        for sub in res["rawDomains"]:
            if not sub.startswith('*') and "." + domain in sub and not subdomains.__contains__(sub):
                subdomains.append(sub)


def passivetotal():
    console.print(info + "Gathering data from [i]PassiveTotal[/i]…")
    auth = (passivetotal_api_key, passivetotal_api_secret)
    response = requests.get(f"https://api.passivetotal.org/v2/enrichment/subdomains?query={domain}",
                            auth=auth, stream=True)
    data = json.loads(response.text)
    for sub in data["subdomains"]:
        if not subdomains.__contains__(sub + "." + domain):
            subdomains.append(sub + "." + domain)


def censys():
    console.print(info + "Gathering data from [i]Censys[/i]…")
    page = pages = 1
    while page <= pages:
        headers = {"Content-Type": "application/json", "Accept": "application/json"}
        auth = (censys_api_id, censys_api_secret)
        # "parsed.extensions.subject_alt_name.dns_names"
        data = {"query": domain, "page": page, "fields": ["parsed.names"]}
        response = requests.post("https://www.censys.io/api/v1/search/certificates",
                                 headers=headers, json=data, auth=auth, stream=True)
        data = json.loads(response.text)
        pages = data["metadata"]["pages"]
        for res in data["results"]:
            pn = res["parsed.names"]
            for sub in pn:
                sub = sub.replace("http://", "")
                sub = sub.replace("https://", "")
                if "." + domain in sub and not sub.startswith("*") and not subdomains.__contains__(sub):
                    subdomains.append(sub)
        page = page + 1


def riddler():
    console.print(info + "Gathering data from [i]Riddler[/i]…")
    response = requests.get(f"https://riddler.io/search/exportcsv?q=pld:{domain}", stream=True)
    data = csv.reader(line.decode('utf-8') for line in response.iter_lines())
    next(data)
    next(data)
    for row in data:
        if not subdomains.__contains__(row[4]):
            subdomains.append(row[4])


def facebook():
    console.print(info + "Gathering data from [i]Facebook[/i]…")
    response = requests.get(
        f"https://graph.facebook.com/certificates?query={domain}&fields=domains&limit=10000&access_token={facebook_access_token}",
        stream=True)
    data = json.loads(response.text)
    for res in data["data"]:
        for sub in res["domains"]:
            if not sub.startswith('*') and not subdomains.__contains__(sub):
                subdomains.append(sub)


def binaryedge():
    console.print(info + "Gathering data from [i]BinaryEdge[/i]…")
    page = pages = 1
    while page <= pages:
        headers = {"X-Key": binaryedge_api_key}
        response = requests.get(f"https://api.binaryedge.io/v2/query/domains/subdomain/{domain}?page={page}",
                                headers=headers, stream=True)
        data = json.loads(response.text)
        pages = data["pagesize"]
        for sub in data["events"]:
            if not subdomains.__contains__(sub):
                subdomains.append(sub)
        page = page + 1


def whoisxmlapi():
    console.print(info + "Gathering data from [i]WhoisXML API[/i]…")
    response = requests.get(
        f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={whoisxmlapi_api_key}&domainName={domain}", stream=True)
    data = json.loads(response.text)
    print(data)
    for res in data["result"]["records"]:
        sub = res["domain"]
        if not subdomains.__contains__(sub):
            subdomains.append(sub)


def spyse():
    console.print(info + "Gathering data [i]Spyse[/i]…")
    headers = {'Authorization': f'Bearer {spyse_api_key}'}
    response = requests.get(f"https://api.spyse.com/v3/data/domain/subdomain?domain={domain}",
                            headers=headers, stream=True)
    data = json.loads(response.text)
    print(data)


def enum(arguments):
    threads = []
    with console.status("[bold green] Please, wait. Processing data..."):
        with ThreadPoolExecutor(max_workers=20) as executor:
            try:
                threads.append(executor.submit(certspotter))
                threads.append(executor.submit(shodan))
                threads.append(executor.submit(omnisint))
                threads.append(executor.submit(hackertarget))
                threads.append(executor.submit(dns_bufferover))
                threads.append(executor.submit(tls_bufferover))
                threads.append(executor.submit(sublist3r))
                threads.append(executor.submit(virustotal))
                threads.append(executor.submit(threatcrowd))
                threads.append(executor.submit(securitytrails))
                threads.append(executor.submit(threatminer))
                threads.append(executor.submit(alienvault))
                threads.append(executor.submit(urlscan))
                threads.append(executor.submit(crt))
                threads.append(executor.submit(anubis))
                threads.append(executor.submit(dnsdb))
                threads.append(executor.submit(recondev))
                threads.append(executor.submit(censys))
                threads.append(executor.submit(riddler))
                threads.append(executor.submit(facebook))
                threads.append(executor.submit(binaryedge))
                # WIP: threads.append(executor.submit(whoisxmlapi))
                # WIP: threads.append(executor.submit(spyse))

                executor.shutdown(wait=True)
            except KeyboardInterrupt:
                threads.clear()
                executor.shutdown()
                console.print("\n" + success + "Goodbye, friend!")
                exit(0)

    # remove tld from subdomains
    if domain in subdomains:
        subdomains.remove(domain)

    if arguments.output is not None:
        console.print("\n" + success + "Saving " + str(len(subdomains)) + " subdomains to " + arguments.output + "!")
        with open(arguments.output, 'w') as file:
            for sub in subdomains:
                file.write(sub + "\n")
    else:
        console.print("\n" + success + "Found " + str(len(subdomains)) + " subdomains:")
        for sub in subdomains:
            print(sub)


def args():
    parser = argparse.ArgumentParser(usage="python3 subzero.py [domain]",
                                     description="Passive subdomain enumeration tool for bug-bounty hunters & "
                                                 "penetration testers.")
    parser.add_argument('-v', '--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('domain', metavar='[domain]', action='store', help='specifies the target domain')
    parser.add_argument("-o", "--output", action="store", dest="output", help="Specifies the output file.")
    return parser.parse_args()


if __name__ == "__main__":
    os.system("cls" if os.name == "nt" else "clear")
    print(banner)
    domain = args().domain
    console.print(success + "Target domain: [bold green]" + domain + "[/bold green]\n")
    enum(args())
