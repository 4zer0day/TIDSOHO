# TIDSOHO

FYP 2k21

Prerequisite

Setting Up Kali Linux onto the Raspberry Pi

There are 3 main things that is needed before the installation process, and it is as follows:
- Balena Etcher (to burn Micro SD card with OS Image)
- Kali Linux ARM Images (to run as the main OS)
- Monitor (to display the installation process)

Below are the steps needed for the setup:
1. Format the Micro SD card
2. Flash the Micro SD card with Kali Linux ARM Images using Balena Etcher
3. Edit the config.txt file for connecting Raspberry Pi with the Monitor.
4. Uncomment # for hdmi_force_hotplug=1 , hdmi_group=2, and hdmi_mode=35
5. Eject the Micro SD card and insert it into the Raspberry Pi.
6. Power on the monitor and connect it with the Raspberry Pi using hdmi port to boot up the Kali Linux.

Setting Kali Linux Installation
Below are the steps needed for the setup:
1. Apt-get update (downloads packages from the repo and updates to the newest version).
2. Apt-get upgrade (install the newer versions of the package that you already have).
3. Apt-dist upgrade (upgrades and remove any packages as needed from the system).

OpenSSH installation
Below are the steps needed for the installation:
1. Apt-get install openssh openssh-server openssh-client (openssh installation)
2. rm /etc/ssh/ssh_host* (Remove the old ssh host keys)
3. dpkg-reconfigure openssh-server (Reconfigure open ssh server)
4. systemctl enable ssh (To enable ssh on boot)
5. systemctl start ssh.service (To start the ssh service)
6. service ssh start (Another way to activate the ssh incase if it is still down)

How to SSH onto Raspberry Pi
Below are the steps needed to SSH onto the Raspberry Pi:
1. Open terminal on the Raspberry Pi and type “ifconfig” to search for the IP address.
2. Use CMD by issuing this command “ssh kali@[Raspberry Pi ip address]”.
3. Insert the root password of the Kali Linux.

Getting API Key using BotFather on Telegram
Below are the steps needed to get API key from BotFather
1. Issue /newbot command to create a new bot.
2. Give a name the bot and botfather will give an API key to you.
3. The API key will be used when setting up the TIDSOHO.py script.

Below are the steps needed to get TIDSOHO python script up and running at the Raspberry Pi.
1. apt-get install python3 python3-pip (pip3 will be used to install all the package requirement in txt file)
2. pip3 install -r requirements.txt (netaddr, netifaces, python-telegram-bot, python-nmap, requests)
3. If you failed to install the requirement the requirement because of SSL problem use this command “pip install --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org <package_name>”.
4. sudo apt remove ca-certificates (Remove the CA if problem still persist)
5. sudo apt install ca-certificates (Install it again to make sure CA is properly repaired)
6. curl -I https://www.gnu.org/ (Test if the SSL certs is allowed)
7. pip command should work fine as the core problem is already being fix.

[Main Part]

Below are the steps needed to get TIDSOHO python script up and running at the raspberry pi.

1. Issue this command “git clone https://github.com/deadrepo/TIDSOHO ”
2. Issue this command “python3 setup.py” at the terminal on TIDSOHO folder
3. Insert the network interface and API Key when asked
4. Insert the Verification code to the telegram for confirmation
5. Config.cfg file will be created and TIDSOHO.py main script can be run by issuing “python3 TIDSOHO.py”
Figure
6. A message will be given by the Telegram bot that the bot is successfully started

Below are some of the available commands of TIDSOHO on Telegram
1. /help is a command that will display all of the available commands.
2. /ping is a command to see if a connection is made between the raspberry pi and telegram bot.
3. /scan is a command to see the available devices inside of the network. The information will then be given to the Telegram
4. /scanip is a command to scan a specific IP Address inside of the network. The information such as MAC address and open port will be given to the Telegram.
5. /DC is command to drop the internet connection of the targeted user.

