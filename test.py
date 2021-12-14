#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# setup.py

import os, time, sys
from telegram import Update
from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext

if os.geteuid() != 0:
    print("[!] Please run the TIDSOHO.py setup as root!")
    exit()

GREEN = '\033[1m' + '\033[32m'
WHITE = '\033[1m' + '\33[97m'
END = '\033[0m'

header = """				                 _____________________________

						 |__   __|_   _|  __ \ / ____|

						    | |    | | | |__) | (___  

						    | |    | | |  ___/ \___ \ 

						    | |   _| |_| |     ____) |

						   _|_|_ |_____|_|   _|_____/ 

						  / ____|/ __ \| |  | |/ __ \ 

						 | (___ | |  | | |__| | |  | |

						  \___ \| |  | |  __  | |  | |

						  ____) | |__| | |  | | |__| |

						 |_____/ \____/|_|  |_|\____/ 

									      

						  """


if __name__ == '__main__':

    noRequirements = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "--norequirements":
            noRequirements = True

    if not noRequirements:
        try:
            print(header + """          v1.0 """ + WHITE + """by FYP 2022 (TIDSOHO)    """ + "\n" + END)
        except:
            print(header + """                         v1.0 """ + WHITE + """by TIDSOHO   """ + "\n" + END)


        try:
            print("[+] Installing requirements in 5 seconds... Press CTRL + C to skip.")
            time.sleep(5)
            print("[+] Installing requirements...")
            os.system("sudo apt update")
            os.system("sudo apt purge netcat netcat-openbsd netcat-traditional -y")
            os.system("sudo sudo apt install dsniff netcat-traditional nmap tcpdump python3-pip python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg62-turbo-dev zlib1g-dev screen -y")
            os.system("python3 -m pip install -r " + os.path.dirname(os.path.realpath(__file__)) + "/" + "requirements.txt")
            os.execl(sys.executable, sys.executable, os.path.dirname(os.path.realpath(__file__)) + "/setup.py", "--norequirements")
        except:
            print("[+] Requirements install skipped...")

    print("\n\n[I] Step 1 / 3:\n")
    print("[+] Please enter the name of the network interface " +\
            "connected/will be connected to the target LAN. Default " +\
            "wired interface is 'eth0', and the default wireless " +\
            "interface is 'wlan0' on most systems, but you can check it " +\
            "in a different terminal with the 'ifconfig' command.")
    while True:
        interface = input("\n[?] Interface to use: ")
        print("\n\n[!?!] Are you sure that '" + str(interface) +\
        "' is the correct interface? If the interface is not correct your " +\
        "device's network interfaces will may be disabled temporary!! " +\
        "(the script is going to enable hotswap on the interface "+\
        "with allow-hotplug in /etc/network/interfaces)\n")
        interface_confirm = input("[?] Use '" + str(interface) + "'? (y/N): ")
        if interface_confirm.lower() == "y":
            break
    os.system("clear")
    print("[+] Interface '" + interface + "' set.")
    print("\n\n[I] Step 2 / 3:\n")
    print("[+] Please create a Telegram API key by messaging @BotFather on " +\
            "Telegram with the command '/newbot'.\n\nAfter this, @BotFather "+\
            "will ask you to choose a name for your bot. This can be "+\
            "anything you want.\n\nLastly, @BotFather will ask you for a "+\
            "username for your bot. You have to choose a unique username "+\
            "here which ends with 'bot'. For example: autobot. Make note "+\
            "of this username, since later you will have to search for this "+\
            "to find your bot, which TIDSOHOBot will be running on.\n\nAfter "+\
            "you send your username of choise to @BotFather, you will "+\
            "recieve your API key. Please enter it here:\n")
    telegram_api = input("[?] Telegram API key: ")
    os.system("clear")
   
    
    import json
    print("[+] Generating config file...")
    config_object = {"interface": interface, "telegram_api": telegram_api, "admin_chatid": 1578801265}
    config_json = json.dumps(config_object)
    with open(os.path.dirname(os.path.realpath(__file__)) + "/config.cfg", "w") as f:
        f.write(config_json)
        f.close()
    os.system("clear")
    print("[+] Config file generated successfully.")
    print("[+] config.cfg file will now appear in your folder.")
    time.sleep(5)
    print("[+] You can proceed an run TIDSOHO.py")


    
