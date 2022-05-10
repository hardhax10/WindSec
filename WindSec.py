# Windows 10 hardening script
# Hardik Purohit
# 15-04-2022

#################################################################################################################################################################
#                                                   Recommeded : Run this script in Administrator mode                                                          #
#################################################################################################################################################################

# Importing OS module for System calls.
import os

# Checking for OS Version
import platform
import string



blue1 = '\u001b[34m'
blue2 = '\u001b[0m'
out_check = 0 
os_ver = platform.platform()
def oscheck():
    check = "Windows" in os_ver
    return check  


# If not Windows the give error
if oscheck():
    print("\nYou are running on Windows Version:" + os_ver)
else:
    print("\nYou are not Olsn a Windows Machine \nThis Version is for Windows OS Hardening. It cannot work in other Operating Systems")
    exit()

# Selecting Which mode to select? 1.Automatic, 2. Manual
def flow_mode():
    
    # print("Select Mode")
    print("\n[1] Auto Pilot Mode\n[2] Manual Mode")
    while True:
        mode = input("\nEnter Mode:").lower().strip()
        if mode == "back":
            break
        else:
            if mode == "use 1" or mode == "use Auto Pilot":
                print("\nStaring Automatic Configurations.")
                return 1
                break
            elif mode == "use 2" or mode == "use Manual":
                print("\nStaring Manual Configurations")
                return 2
                break
            else:
                print('\nGiven input have some errors...\nTry using "use <mode-number/name>"')
                flow_mode()

def privacy():
    x=flow_mode()
    if x==1:
        print("\n1 selected")
        tailored_event()
        cortana()
    elif x==2:
        print("\n2 selected")
        print("\nThis feature is yet to be enabled")

def security():
    x=flow_mode()
    if x==1:
        print("\n1 selected")
        user_acc_ctrl()
    elif x==2:
        print("\n2 selected")

#################################################################################################################################################################
#                                                          Main Functions of Privacy                                                                            #
def tailored_event():
    print("\nPrivacy - Disable tailored experiences with diagnostic data.")

    out_check = os.system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f')
    if out_check == 0:
        print("Tailored Adverts have been disabled")
    else:
        print("\nUnable to disable Tailored Adverts")

def defender():
    print("\nTrying to Enable Windows Defender Antivirus...")
    out_check = os.system('reg delete “HKLM\Software\Policies\Microsoft\Windows Defender” /v DisableAntiSpyware /f')
    if out_check == 0:
        print("\nWindows Defender Antivirus is Enabled!.")
    else:
        print("\nUnable to Enable Windows Defender Antivirus.")

def updates():
    print("\nTrying to Enable Automatic Updates...")
    out_check = os.system('reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v NoAutoUpdate /t Reg_DWORD /d 0 /f')
    if out_check == 0:
        print("\nWindows Defender Antivirus is Enabled!.")
    else:
        print("\nUnable to Enable Windows Defender Antivirus.")

def services():
    

def cortana():
    print("\nTrying to Disable Cortana...")
    out_check = os.system('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f')
    if out_check == 0:
        print("\nCortana have been disabled.")
    else:
        print("\nUnable to disable cortana.")

def user_acc_ctrl():
    out_check = os.system('ADD HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 2 /f')
    if out_check == 0:
        print('\nUser Account Control set to maximum')
    else:
        print('\nUser Account Control was unable to configure')
    
#                                                                                                                                                               # 
#################################################################################################################################################################


# Main Console Window of the tool
def console():
    while True:
        console_input=input("\nWindSec --> ").lower().strip()
        if console_input == "exit":
            break
        else:
            if console_input == "mode": # For Selecting a mode 
                flow_mode()
            elif console_input == "privacy":  # For enabling privacy in Windows
                privacy()
            else:
                print("Entered input is not a valid command in WindSec")

console()