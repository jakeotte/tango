import argparse
import requests
import ipaddress
from time import sleep
from lxml.html import fromstring
import random
import bs4
from colorama import Fore
from colorama import Style
from colorama import init as colorama_init
from multiprocessing import Pool
import warnings
warnings.filterwarnings("ignore")


### Banner
banner = f"""
{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}{Fore.YELLOW}{Style.BRIGHT}

TANGO TEMP SPLASH   
                                  {Fore.WHITE}2ptr

{Style.RESET_ALL}{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}"""

### Parser
parser = argparse.ArgumentParser(
                    prog='tango',
                    description='initial access for AD networks',
                    epilog='https://github.com/2ptr/tango')

inputgroup = parser.add_argument_group('targets')
inputgroup = inputgroup.add_mutually_exclusive_group(required=True)

# Targets group
inputgroup.add_argument('-r', help='Subnet range to scan (10.10.10.0/24)', metavar='10.10.10.0/24')
inputgroup.add_argument('-rf', help='Subnet ranges file (10.10.10.0/24, 10.10.11.0/24, etc.)', metavar='subnets.txt')
inputgroup.add_argument('-tf', help='Newline-delimited single target file (10.10.10.10, 10.10.10.11, etc.)', metavar='hosts.txt')

# Configurable options
parser.add_argument('-p', help='Port list to test. Default is 80,443.', default='80,443', metavar='[ports]')
parser.add_argument('-t', help='Number of threads. Default is 10.', default=10, type=int, metavar='[num]')
parser.add_argument('-ua', help='User-agent for requests. Default is Windows/Mozilla.', default='Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0', metavar='"Mozilla 1.x"')
parser.add_argument('--random', help='Randomly select hosts from subnets.', action="store_true")

# Other options
parser.add_argument('-o', help='Output file for alive hosts. Defaults to web-hosts.txt.', type=str, default='web-hosts.txt',  metavar='web-hosts.txt')
parser.add_argument('--debug', help='Show debug information.', action="store_true")

args = parser.parse_args()
ports = args.p.split(',')

headers = {
    "User-Agent" : args.ua
}

### Settings banner
settings_blob = f"""{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Scan settings:
- Ports : {args.p}
- Target Selection : {'Random' if args.random else 'Sequential'}
- Thread count : {args.t}
- User-agent: {args.ua}
>> Press Enter to start scan..."""

# Construct a list of targets (IP:PORT) from CIDR ranges and target files.
def getTargetList():
    targets = []
    ### CIDR Subnet Mode
    if(args.r):
        ips = [str(ip) for ip in ipaddress.IPv4Network(args.r)]
        for ip in ips:
            for port in ports:
                targets.append(f"{ip}:{port}")
        

    ### File with CIDR Subnets
    if(args.rf):
        with open(args.rf) as file:
            ranges = [line.rstrip() for line in file]        
        for range in ranges:
            ips = [str(ip) for ip in ipaddress.IPv4Network(range)]
            for ip in ips:
                for port in ports:
                    targets.append(f"{ip}:{port}")
        debug(f"{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Loaded {len(ranges)} subnets from {args.rf}.")


    ### File with raw targets
    if(args.tf):
        with open(args.tf) as file:
            ips = [line.rstrip() for line in file]
        for ip in ips:
            for port in ports:
                targets.append(f"{ip}:{port}")

    return targets


# checkIIS: return TRUE if the web server is an IIS server.
def checkIIS(protocol, target, response):
    try:
        server = response.headers['Server']
        if "IIS" in server:
            print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} {Style.RESET_ALL}{protocol}://{target} is an IIS server.")
            return True
    except:
        return False

# Scan a single target (192.168.20.1:80).
# Returns the target for alive and None for dead.
def scanSingle(target):
    try:
        # HTTPS for 443s
        if target.split(":")[-1] == "443":
            response = requests.get(f"https://{target}", headers=headers, timeout=1, verify=False)
            if checkIIS("https", target, response):
                scanNTLM(target)
        # HTTP
        else:
            response = requests.get(f"http://{target}", headers=headers, timeout=1, verify=False)
            if checkIIS("http", target, response):
                scanNTLM(target)

    except requests.exceptions.SSLError:
        # HTTPS with additional SSL error
        print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} {target} is up but has an SSL error.")

    except requests.exceptions.ReadTimeout:
        # Timeouts
        print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} {target} timed out, but is likely up.")
    
    except:
        debug(f"[x] {target}")
        return None
        
    return target


# Scan a given IIS server for NTLM authentication endpoints - ADCS and SCCM.
def scanNTLM(target):
    auth_header = ""
    try:
        response = requests.get(f"http://{target}/", headers=headers, timeout=1, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    try:
        response = requests.get(f"https://{target}/", headers=headers, timeout=1, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    if "NTLM" in auth_header:
        print(f"{Style.BRIGHT}{Fore.RED}[!] UNKNOWN - NTLM AUTHENTICATION ENABLED ({target}){Style.RESET_ALL}")
    
    auth_header = ""
    try:
        response = requests.get(f"http://{target}/certsrv/", timeout=1, headers=headers, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    try:
        response = requests.get(f"https://{target}/certsrv/", timeout=1, headers=headers, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    if "NTLM" in auth_header:
        print(f"{Style.BRIGHT}{Fore.RED}[!] ADCS - NTLM AUTHENTICATION ENABLED ({target}){Style.RESET_ALL}")

    auth_header = ""
    try:
        response = requests.get(f"http://{target}/ccm_system_windowsauth/request", headers=headers, timeout=1, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    try:
        response = requests.get(f"https://{target}/ccm_system_windowsauth/request", headers=headers, timeout=1, verify=False)
        auth_header = response.headers["WWW-Authenticate"]
    except:
        pass
    if "NTLM" in auth_header:
        print(f"{Style.BRIGHT}{Fore.RED}[!] SCCM - NTLM AUTHENTICATION ENABLED ({target}){Style.RESET_ALL}")

# Debug messages
def debug(msg):
    if args.debug:
        print(f"{Style.DIM}{msg}{Style.RESET_ALL}")


def main():
    print(banner)
    print(settings_blob)
    input()

    ### Generate target list from usage mode
    targets = getTargetList()
    debug(f"[?] Targets: {targets}")
    print(f"{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Loaded {len(targets)} targets.")
    
    ### Scan targets
    alive = []
    scanned = []

    # random scanning
    if args.random:
        target = random.choice(targets)
        for i in targets:
            while target in scanned:
                target = random.choice(targets)

            # Returns true if the target is alive.
            if scanSingle(target):
                alive += [target]
            scanned += [target]

            # Sleep and jitter
            sleep(args.s)
    
    # non-random scanning
    else:
        with Pool(args.t) as p:
            p.map(scanSingle, targets)

    return

if __name__ == '__main__':
    main()