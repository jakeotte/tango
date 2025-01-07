import argparse
import requests
import ipaddress
import ping3
import socket
import dns.resolver
from src.ldapscan import *
from colorama import Fore, Style
from multiprocessing import Pool
import warnings
warnings.filterwarnings("ignore")


### Banner
banner = f"""
{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}{Style.BRIGHT}

                     TANGO - Internal Network Recon
                                  2ptr

{Style.RESET_ALL}{Fore.BLUE}{Style.BRIGHT}*****************************************************************************{Style.RESET_ALL}"""

### Parser
parser = argparse.ArgumentParser(
                    prog='tango',
                    description='initial access for AD networks',
                    epilog='https://github.com/2ptr/tango')

parser.add_argument('-d', help='Domain name (company.local).', metavar='company.local', required=True)
parser.add_argument('-ns', help='DNS server IP address.')
inputgroup = parser.add_argument_group('targets')
inputgroup = inputgroup.add_mutually_exclusive_group(required=True)

# Targets group
inputgroup.add_argument('-r', help='Subnet range to scan (10.10.10.0/24)', metavar='10.10.10.0/24')
inputgroup.add_argument('-rf', help='Subnet ranges file (10.10.10.0/24, 10.10.11.0/24, etc.)', metavar='subnets.txt')
inputgroup.add_argument('-tf', help='Newline-delimited single target file (10.10.10.10, 10.10.10.11, etc.)', metavar='hosts.txt')

# Configurable options
parser.add_argument('-p', help='Port list to test. Default is 80,443.', default='80,443', metavar='[ports]')
parser.add_argument('-t', help='Number of threads. Default is 10.', default=10, type=int, metavar='[num]')

# Other options
parser.add_argument('-o', help='Output file for alive hosts. Defaults to tango-out.txt.', type=str, default='tango-out.txt',  metavar='tango-out.txt')
parser.add_argument('--debug', help='Show debug information.', action="store_true")

args = parser.parse_args()
ports = args.p.split(',')

headers = {
    "User-Agent" : "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:133.0) Gecko/20100101 Firefox/133.0"
}

### Settings banner
settings_blob = f"""{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Scan settings:
- Domain : {args.d}
- DNS Server : {args.ns if args.ns else "Default"}
- Ports : {args.p}
- Thread count : {args.t}
>> Press Enter to start scan..."""

# getDomainControllers : Retrieve domain controllers via SRV record,
# verify alive status via ICMP and SMB ports, and finally check signing requirements.
def getDomainControllers(domain):
    # Construct DNS resolver
    dns_resolver = dns.resolver.Resolver()
    dns_resolver.nameservers = [args.ns] if args.ns else dns_resolver.nameservers[0]
    try:
        print(f"{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Using DNS server {dns_resolver.nameservers[0]}")
        # Resolve LDAP server query
        result = dns_resolver.resolve(f'_ldap._tcp.dc._msdcs.{domain}', 'SRV', lifetime=10)
        for host in result.rrset:
            # Extract hostname
            host = host.to_text().split(" ")[-1][:-1]
            print(f"{Style.BRIGHT}{host}{Style.RESET_ALL}")
            # Test ICMP
            r = ping3.ping(host)
            if r:
                print(f"{Fore.GREEN}    [+] ICMP : ALIVE{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}    [X] ICMP : DEAD{Style.RESET_ALL}")
            # Check SMB
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            try:
                result = sock.connect_ex((f"{host}",445))
                if result == 0:
                    print(f"{Fore.GREEN}    [+] SMB : ALIVE{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}    [X] SMB : DEAD{Style.RESET_ALL}")
            except:
                print(f"{Fore.RED}    [X] SMB : DEAD{Style.RESET_ALL}")

            match do_check(host, domain):
                case "NEVER":
                    print(f"{Fore.GREEN}    [+] LDAPS BINDING : NEVER{Style.RESET_ALL}")
                case "SUPPORTED":
                    print(f"{Fore.YELLOW}    [~] LDAPS BINDING : WHEN SUPPORTED{Style.RESET_ALL}")
                case "REQUIRED":
                    print(f"{Fore.RED}    [X] LDAPS BINDING : REQUIRED{Style.RESET_ALL}")
                case _:
                    print(f"{Fore.RED}    [X] LDAPS BINDING : SCAN ERROR{Style.RESET_ALL}")

    except dns.resolver.NXDOMAIN:
        print(f"{Fore.RED}[X] DNS name does not exist. Skipping DC checks...{Style.RESET_ALL}")
    except dns.resolver.LifetimeTimeout:
        print(f"{Fore.RED}[X] DNS query timed out. Skipping DC checks...{Style.RESET_ALL}")


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
        debug(f"[?] Loaded {len(ranges)} subnets from {args.rf}.")


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
            print(f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} IIS SERVER - {protocol}://{target}")
            return True
    except:
        return False

# Scan a single target (192.168.20.1:80).
# Returns the target for alive and None for dead.
def scanWeb(target):
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
        print(f"{Style.BRIGHT}{Fore.YELLOW}[~]{Style.RESET_ALL} {target} is up but has an SSL error.")

    except requests.exceptions.ReadTimeout:
        # Timeouts
        print(f"{Style.BRIGHT}{Fore.YELLOW}[~]{Style.RESET_ALL} {target} timed out but is likely up.")
    
    except:
        debug(f"[x] {target}")
        return None
        
    return target


# Scan a given IIS server for NTLM authentication endpoints - ADCS and SCCM.
def scanNTLM(target):
    auth_header = ""
    for uri in ['/','/certsrv/','/ccm_system_windowsauth/request']:
        debug(f"[?] Testing {target}{uri} for NTLM...")
        try:
            response = requests.get(f"http://{target}{uri}", headers=headers, timeout=1, verify=False)
            auth_header = response.headers["WWW-Authenticate"]
        except:
            pass
        try:
            response = requests.get(f"https://{target}{uri}", headers=headers, timeout=1, verify=False)
            auth_header = response.headers["WWW-Authenticate"]
        except:
            pass
        if "NTLM" in auth_header:
            print(f"{Style.BRIGHT}{Fore.RED}    [!] NTLM AUTHENTICATION ENABLED: {Style.RESET_ALL}{target}{uri}{Style.RESET_ALL}")

def scanMSSQL(target):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(2)
    try:
        result = sock.connect_ex((f"{target}",1433))
        if result == 0:
            print(f"{Fore.GREEN}{Style.BRIGHT}[+] MSSQL - {Style.RESET_ALL}{target}{Style.RESET_ALL}")
        else:
            debug(f"[?] {target}")
    except:
        debug(f"[?] {target}")

# Debug messages
def debug(msg):
    if args.debug:
        print(f"{Style.DIM}{msg}{Style.RESET_ALL}")


def main():
    print(banner)
    print(settings_blob)
    input()

    ### Domain Controllers
    print(f"{Style.BRIGHT}{Fore.BLUE}***** {Fore.WHITE}Domain Controllers{Fore.BLUE} ****************************************************{Style.RESET_ALL}")
    dcs = getDomainControllers(args.d)

    ### Generate target list from usage mode
    print(f"{Style.BRIGHT}{Fore.BLUE}\n***** {Fore.WHITE}HTTP Relay Targets{Fore.BLUE} ****************************************************{Style.RESET_ALL}")
    targets = getTargetList()
    debug(f"[?] Targets: {targets}")
    print(f"{Style.BRIGHT}{Fore.MAGENTA}[*]{Style.RESET_ALL} Loaded {len(targets)} targets.")

    ### Scan web targets
    with Pool(args.t) as p:
        p.map(scanWeb, targets)

    ### Scan MSSQL targets
    print(f"{Style.BRIGHT}{Fore.BLUE}\n***** {Fore.WHITE}MSSQL Relay Targets{Fore.BLUE} ***************************************************{Style.RESET_ALL}")
    targets = getTargetList()
    targets = [target.split(":")[0] for target in targets] # oops
    with Pool(args.t) as p:
        p.map(scanMSSQL, targets)

    return

if __name__ == '__main__':
    main()