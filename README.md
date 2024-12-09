# ldGo
Command line link discovery tool written in GoLang

Working in Windows 11 / Linux / Mac

# Depends on nPcap / libPcap see below for install instructions

## WINDOWS:

Download and install nPcap:

https://npcap.com/#download

You may need admin to run

## LINUX:

Install libpcap0.8 to run the tool:

    sudo apt install libpcap0.8 

Install libpcap-dev to build the project:

    sudo apt install libpcap-dev

If you install libpcap0.8 and the program still fails, try installing the dev version as well.

You will likely need to run as sudo

## Mac

No install requirements in my testing. I just installed GoLang on a mac, cloned the repo, built it and it worked. It is possible that this has installed something, I ran on a clean desktop Mac with Apple silicon and it also worked. 

# Basic Usage
Navigate a command line such as Powershell to the folder containing ldgo.exe, or add the containing folder to your system path to use it as a command from anywhere.

To listen for packets, you will need the ID or name of the NIC, as returned by this program. The default behaviour is to prompt the user to run help and list the adapors.

The ID should always be the same unless you add/remove an adapter because the list is sorted alphabetically before being displayed.

To only list the adaptors Run:

    ldgo.exe -l 

You should see an output similar to the below:

![image](https://github.com/user-attachments/assets/b3206ed2-1807-4b9c-9412-77597094d676)


You can now run:
    
    ldgo.exe -i 1
  
To listen on the Ethernet interface shown. 

You can also select an interface by specifying a substring of the Name or Description. 

    ldgo.exe -n Ethernet

While this readme covers the basics, use the following command to list all available flags:
    
    ldgo.exe -h

## Known issues Linux
On Linux the program waits for some time after a successful capture is complete. You can ctrl+c to cancel the operation but this is not desired behaviour. No further packets are captured after the first, and the time is usually less than the remaining timeout.

Network adapters don't have descriptions making them harder to identify, usually the IPV4 address is a good indicator.

Running in WSL I was unable to capture packets on any interface.

## Known issues Mac

Network adapters don't have descriptions and show IPV6 addresses, making them harder to identify. 
