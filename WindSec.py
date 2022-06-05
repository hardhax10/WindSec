# Windows 10 hardening script
# Hardik Purohit
# 15-04-2022

#################################################################################################################################################################
#                                                               Recommeded                                                                                     #
#                                                               [1] Run this script in Administrator mode                                                      #
#                                                               [2] This Application can be only run in windows enviroment                                     #
#                                                               [3] First run the requirement.exe to run this application efficiently                          #
#################################################################################################################################################################

# Importing OS module for System calls.
import os

# Checking for OS Version
import platform
import string


perform = {
    "list-update" : 'powershell -command "Get-Windowsupdate";',
    "install-update" : 'powershell -command "Install-WindowsUpdate"',
    "auto-update" : 'reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v NoAutoUpdate /t Reg_DWORD /d 0 /f',
    "notify-update" : 'reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v AUOptions /t Reg_DWORD /d 3 /f',
    "update-source" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 1 /f',
    "update-office" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d 1 /f',

    "enable-defender" : 'reg delete “HKLM\Software\Policies\Microsoft\Windows Defender” /v DisableAntiSpyware /f',
    "all-defender" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f',
    "UAC" : 'reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 2 /f',
    "anonymous-access" : 'reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v restrictanonymous /t Reg_DWORD /d 1 /f',
    "anonymous-SAM-enum" : 'reg add HKLM\System\CurrentControlSet\Control\Lsa\ /v restrictanonymoussam /t Reg_DWORD /d 1 /f',
    

}
blue1 = '\u001b[34m'
blue2 = '\u001b[0m'
out_check = 0
flow_check = 0
os_ver = platform.platform()
def oscheck():
    check = "Windows" in os_ver
    return check


# If not Windows the give error
if oscheck():
    print("\n[+] You are running on Windows Version:" + os_ver)
else:
    print("\n[-] You are not on a Windows Machine \n[-] This Version is for Windows OS Hardening. It cannot work in other Operating Systems")
    exit()

# Selecting Which mode to select? 1.Automatic, 2. Manual
def flow_mode():
    global flow_check
    # print("Select Mode")
    print("\n[1] Auto Pilot \n[2] Manual")
    while True:
        mode = input("\nEnter Mode:").lower().strip()
        if mode == "back" or mode == "exit":
            break
        else:
            if mode == "use 1" or mode == "use auto pilot":
                print("\n[+] Staring Automatic Configurations.")
                flow_check = 1
                break
            elif mode == "use 2" or mode == "use manual":
                print("\n[+] Staring Manual Configurations")
                flow_check = 2
                break
            else:
                print('\nGiven input have some errors...\nTry using "use <mode-number/name>"')

def privacy():
    global flow_check
    global perform
    if flow_check == 0:
        print("[-] Select Mode First")
    else:
        if flow_check==1:
            print("\n1 selected")
            ################################
            for x in perform:
                actions(perform[x])
            #################################
        elif flow_check==2:
            print("\n2 selected")
            print("\nThis feature is yet to be enabled")
        else:
            print("First Specify which mode to work with.")

def security():
    if flow_check==1:
        print("\n1 selected")
    elif flow_check==2:
        print("\n2 selected")

#################################################################################################################################################################
#                                                          Main Functions of Privacy                                                                            #
# def tailored_event():
#     print("\nPrivacy - Disable tailored experiences with diagnostic data.")

#     out_check = os.system('reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Privacy" /v "TailoredExperiencesWithDiagnosticDataEnabled" /t REG_DWORD /d 0 /f')
#     if out_check == 0:
#         print("Tailored Adverts have been disabled")
#     else:
#         print("\nUnable to disable Tailored Adverts")

# def defender():
#     print("\nTrying to Enable Windows Defender Antivirus...")
#     out_check = os.system('reg delete “HKLM\Software\Policies\Microsoft\Windows Defender” /v DisableAntiSpyware /f')
#     if out_check == 0:
#         print("\nWindows Defender Antivirus is Enabled!.")
#     else:
#         print("\nUnable to Enable Windows Defender Antivirus.")

# def updates():
#     print("\nTrying to Enable Automatic Updates...")
#     out_check = os.system('reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v NoAutoUpdate /t Reg_DWORD /d 0 /f')
#     if out_check == 0:
#         print("\nWindows Defender Antivirus is Enabled!.")
#     else:
#         print("\nUnable to Enable Windows Defender Antivirus.")

# def services():
    
#     print("\nTrying to Disable Diagnostics Data Tracking")
#     out_check=os.system("net stop DiagTrack & sc delete DiagTrack")
#     if out_check == 0:
#         print("\nDiagnostic tracking disabled.")
#     else:
#         print("\nUnable to turn diagnostic data turn off.")
    
#     os.system("net stop dmwappushservice & sc delete dmwappushservice")
    
#     os.system("net stop RemoteRegistry & sc config RemoteRegistry start=disabled")
    
#     os.system("net stop RetailDemo & sc config RetailDemo start=disabled")
    
#     os.system("net stop WinRM & sc config WinRM start=disabled")
    
#     os.system("net stop WMPNetworkSvc & sc config WMPNetworkSvc start=disabled")

# def cortana():
#     print("\nTrying to Disable Cortana...")
#     out_check = os.system('reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCloudSearch" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowCortanaAboveLock" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "AllowSearchToUseLocation" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f & reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "DisableWebSearch" /t REG_DWORD /d 1 /f')
#     if out_check == 0:
#         print("\nCortana have been disabled.")
#     else:
#         print("\nUnable to disable cortana.")

# def user_acc_ctrl():
#     out_check = os.system('reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 2 /f')
#     if out_check == 0:
#         print('\nUser Account Control set to maximum')
#     else:
#         print('\nUser Account Control was unable to configure')
def actions(perform):
    out_check = os.system(perform)
    if out_check == 0:
        print('\n[+] DONE!')
    else:
        print('\n[-] FAILED!')

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