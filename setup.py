#!/usr/bin/env python3
# -.- coding: utf-8 -.-
# setup.py


import os, time, sys
from telegram import Update

from telegram.ext import Updater, CommandHandler, MessageHandler, Filters, CallbackContext


if os.geteuid() != 0:
    print("[!] Welcome and please run as Root ")
    exit()

GREEN = '\033[1m' + '\033[32m'
WHITE = '\033[1m' + '\33[97m'
END = '\033[0m'

header = """
                 _______ _____ _____   _____  ____  _    _  ____  
 		|__   __|_   _|  __ \ / ____|/ __ \| |  | |/ __ \ 
   		   | |    | | | |  | | (___ | |  | | |__| | |  | |
   		   | |    | | | |  | |\___ \| |  | |  __  | |  | |
   		   | |   _| |_| |__| |____) | |__| | |  | | |__| |
    		   |_|  |_____|_____/|_____/ \____/|_|  |_|\____/ 
                                                  
                """

if __name__ == '__main__':

    noRequirements = False
    if len(sys.argv) > 1:
        if sys.argv[1] == "--norequirements":
            noRequirements = True

    if not noRequirements:
        try:
            print(header + """    v1.0 """ + WHITE + """by Ikmal and Prof Salman FYP 2021    """ + "\n" + END)
        except:
            print(header + """                         v1.0 """ + WHITE + """by Ikmal and Prof Salman FYP 2021    """ + "\n" + END)


        try:
            print("[!] Installing requirements in 5 seconds... Press CTRL + C to skip.")
            time.sleep(5)
            print("[!] Installing requirements...")
            os.system("sudo apt update")
            # Basic libraries installation
            os.system("sudo apt purge netcat netcat-openbsd netcat-traditional -y")
            os.system("sudo sudo apt install dsniff netcat-traditional nmap tcpdump python3-pip python3-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg62-turbo-dev zlib1g-dev screen -y")

            os.system("python3 -m pip install -r " + os.path.dirname(os.path.realpath(__file__)) + "/" + "requirements.txt")
            os.execl(sys.executable, sys.executable, os.path.dirname(os.path.realpath(__file__)) + "/setup.py", "--norequirements")
        except:
            print("[!] Requirements install skipped...")

    #STEP 1
    print("\n\n[!] Step 1 / 3:\n")
    print("[!] Do enter the name of the network interface " +\
            "'eth0' the default wireless, " +\
            "'wlan0' is used on most systems," +\
            "Not sure? Use 'ifconfig' command.")
    #Confirmation
    while True:
        interface = input("\n[?] Interface to use: ")
        print("\n\n[!?!] Are you sure that '" + str(interface) +\
        "' is the correct interface? If the interface is not correct your " +\
        "device's network interfaces will be disabled for awhile") 
        interface_confirm = input("[?] Use '" + str(interface) + "'? (y/N): ")
        if interface_confirm.lower() == "y":
            break

    os.system("clear")
    #STEP 2
    print("[!] Interface '" + interface + "' set.")
    print("\n\n[!] Step 2 / 3:\n")
    print("[!] Please create a Telegram API key by messaging @BotFather on " +\
            "Telegram with the command '/newbot'.\n\nOnce Completed you'll get the API Key "+\
            "\n\nPlease enter it here:\n")

    telegram_api = input("[?] Telegram API key: ")
    os.system("clear")
    print("\n\n[!] Loading...\n")

    from telegram.ext import Updater, MessageHandler, Filters
    from random import randint
    import telegram
    import json
    
    #STEP 3
    print("\n\n[!] Step 3 / 3:\n")
    print("[!] TIDSOHO will only be accessible to you"+\
            "Please verify yourself.\n\n Send the verification code below TO THE BOT")

    verification_code = ''.join(str(randint(0,9)) for _ in range(6))
    print("\n[!] Verification code to send: " + verification_code)
    admin_chatid = False
    def check_code(update: Update, context: CallbackContext)-> None:
        global admin_chatid
        if update.message.text == verification_code:
            context.bot.send_message(chat_id=update.message.chat_id, text="✅ Verification successful.")
            admin_chatid = str(update.message.chat_id)
        else:
              context.bot.send_message(chat_id=update.message.chat_id, text="❌ Incorrect code.")

    try:
        updater = Updater(token=telegram_api)
    except:
        print("[!] Telegram API token is invalid... Please try again.")
    dispatcher = updater.dispatcher

    verify_handler = MessageHandler(Filters.text, check_code)
    dispatcher.add_handler(verify_handler)

    print("\n[!] Waiting for your message...")
    updater.start_polling()

    while True:
        try:
            if not admin_chatid == False:
                print("\n[!] Congratulations! Device is now successfully integrated!")
                updater.stop()
                break
        except:
            print("\n[!] Incorrect! Please Try Again!")
            updater.stop()
            exit()

    #GENERATING CONFIG.CFG FILE
    print("[!] Generating config file...")
    config_object = {"interface": interface, "telegram_api": telegram_api, "admin_chatid": admin_chatid}
    config_json = json.dumps(config_object)
    with open(os.path.dirname(os.path.realpath(__file__)) + "/config.cfg", "w") as f:
        f.write(config_json)
        f.close()
    os.system("clear")
    print("[!] Config file generated successfully.")
    print("[!] config.cfg file will now appear in your folder.")
    time.sleep(5)
    print("[!] You can proceed an run TIDSOHO.py")
  