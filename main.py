import requests
import dns.resolver 
import time
import colorama
from colorama import Fore
colorama.init()

print(Fore.MAGENTA+'''
  _                 _      _    _       
 | |               | |    | |  | |      
 | |     ___   ___ | | __ | |  | |_ __  
 | |    / _ \ / _ \| |/ / | |  | | '_ \ 
 | |___| (_) | (_) |   <  | |__| | |_) |
 |______\___/ \___/|_|\_\  \____/| .__/ 
                                 | |    
                                 |_|    

''')

print(Fore.GREEN+"")
domain = input("Enter Domain:")

print(Fore.GREEN+"LookUp is working\n")
time.sleep(0.5)

if 'http' not in domain:
    try:
        headers = requests.get("https://"+domain).headers
    except:
        print(Fore.RED+"Warning: Site is using HTTP\n")
        headers = requests.get("http://"+domain).headers
else:
    headers = requests.get(domain).headers

time.sleep(0.25)
print(Fore.GREEN+"Scanning headers.....\n")
time.sleep(0.25)

vulns = []
attacks = []


if "X-Frame-Options" not in headers:
    vulns.append("X-Frame-Options")
    attacks.append("Clickjacking")

if "X-Content-Type-Options" not in headers:
    vulns.append("X-Content-Type-Options")
    attacks.append("MIME-Sniffing")

if "Content-Security-Policy" not in headers:
    vulns.append("Content-Security-Policy")
    attacks.append("XSS Attack")

if "Strict-Transport-Security" not in headers:
    vulns.append("Strict-Transport-Security")
    attacks.append("Man-In-The-Middle(MITM)")


print(Fore.RED+str(len(vulns))+" Vulnerabilities(missing headers) Found!!\n")

print(Fore.CYAN+"Headers Missing-")
for vuln in vulns:
    print(" "+vuln)

print(Fore.MAGENTA+"\nSite is Vulnerable to-")
for attack in attacks:
    print(" "+attack)


print(Fore.YELLOW+"\nDNS Records-")

# A records 
try:
    A_Record = dns.resolver.resolve(domain, 'A') 
    # Printing A record 
    for val in A_Record:
	    print('A Record : ', val.to_text())
except Exception as e:
    print(e)
    pass

# AAAA record
try:
    AAAA_Record = dns.resolver.resolve(domain, 'AAAA') 
    for val in AAAA_Record: 
        print('AAAA Record : ', val.to_text())
except Exception as e:
    print(e)
    pass

# Finding NS record 
try:
    NS_Record = dns.resolver.resolve(domain, 'NS') 
    # Printing NS record 
    for val in NS_Record: 
        print('NS Record : ', val.to_text())
except Exception as e:
    print(e)
    pass

# Finding MX record 
try:
    MX_Record = dns.resolver.resolve(domain, 'MX') 
    # Printing MX record 
    for val in MX_Record: 
        print('MX Record : ', val.to_text())
except Exception as e:
    print(e)
    pass

# Finding SOA record 
try:
    SOA_Record = dns.resolver.resolve(domain, 'SOA') 
    # Printing SOA record 
    for val in SOA_Record: 
        print('SOA Record : ', val.to_text()) 
except Exception as e:
    print(e)
    SOA_Record = ["No answer :( "]

# Finding CNAME record 
try:
    CNAME_Record = dns.resolver.resolve(domain, 'CNAME')
    # Printing CNAME record 
    for val in CNAME_Record: 
        print('CNAME Record : ', val.target) 
except Exception as e:
    print(e)
    pass

# Finding TXT record 
try:
    TXT_Record = dns.resolver.resolve(domain, 'TXT') 
    # Printing TXT record 
    for val in TXT_Record:
        print('TXT Record : ', val.to_text())
except Exception as e:
    print(e)
    TXT_Record = ["No answer :( "]

input("")
