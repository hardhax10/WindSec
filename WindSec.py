# WindSec
# Windows 10 hardening Tool
# Hardik Purohit
# 15-04-2022

#################################################################################################################################################################
#                                                                 Recommeded                                                                                    #
#                                                  [1] Run this script in Administrator mode                                                                    #
#                                                  [2] This Application can be only run in windows enviroment                                                   #
#                                                  [3] First run the requirement.exe to run this application efficiently                                        #
#################################################################################################################################################################
2
import os # Importing OS module for System calls.
import platform # Checking for OS Version
import string
import base64

Security = {
    "list-update" : 'powershell -command "Get-Windowsupdate";',
    "install-update" : 'powershell -command "Install-WindowsUpdate"',
    "auto-update" : 'reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v NoAutoUpdate /t Reg_DWORD /d 0 /f',
    "notify-update" : 'reg add “HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsUpdate\AU” /v AUOptions /t Reg_DWORD /d 3 /f',
    "update-source" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization" /v "DODownloadMode" /t REG_DWORD /d 1 /f',
    "update-office" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v "enableautomaticupdates" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\office\16.0\common\officeupdate" /v "hideenabledisableupdates" /t REG_DWORD /d 1 /f',

    "enable-defender" : 'reg delete “HKLM\Software\Policies\Microsoft\Windows Defender” /v DisableAntiSpyware /f',
    "all-defender" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "DisableAntiSpyware" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender" /v "ServiceKeepAlive" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableIOAVProtection" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection" /v "DisableRealtimeMonitoring" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "CheckForSignaturesBeforeRunningScan" /t REG_DWORD /d 1 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows Defender\Scan" /v "DisableHeuristics" /t REG_DWORD /d 0 /f;reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "ScanWithAntiVirus" /t REG_DWORD /d 3 /f',
    "UAC" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v EnableLUA /t REG_DWORD /d 2 /f',
    "anonymous-access" : 'reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v restrictanonymous /t Reg_DWORD /d 1 /f',
    "anonymous-SAM-enum" : 'reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v restrictanonymoussam /t Reg_DWORD /d 1 /f',
    "ntlmv2" : 'reg add "HKLM\System\CurrentControlSet\Control\Lsa" /v lmcompatibilitylevel /t Reg_DWORD /d 5 /f',
    "auto-logon" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" /v AutoAdminLogin /t REG_SZ /d 0 /f',
    "show-extensions" : 'reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\HideFileExt" /v "CheckedValue" /t REG_DWORD /d 0 /f;reg add "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d 0 /f',
    "spectre-meltdown-protection" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverrideMask" /t REG_DWORD /d 3 /f; wmic cpu get name | findstr "Intel" >nul && (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 0 /f); wmic cpu get name | findstr "AMD" >nul && (reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" /v "FeatureSettingsOverride" /t REG_DWORD /d 64 /f)',
    "disable-smbv1" : '''dism /online /Disable-Feature /FeatureName:"SMB1Protocol" /NoRestart; dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Client" /NoRestart; dism /Online /Disable-Feature /FeatureName:"SMB1Protocol-Server" /NoRestart''',
    "powershell2.0-downgrade" : 'dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2Root" /NoRestart; dism /online /Disable-Feature /FeatureName:"MicrosoftWindowsPowerShellV2" /NoRestart',
    "DHK-increase-4096" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v ServerMinKeyBitLength /t REG_DWORD /d 0x00001000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v ClientMinKeyBitLength /t REG_DWORD /d 0x00001000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\KeyExchangeAlgorithms\Diffie-Hellman" /f /v Enabled /t REG_DWORD /d 0x00000001',
    "disable-rc2" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 40/128" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 56/128" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC2 128/128" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-rc4" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 128/128" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 64/128" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 56/128" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\RC4 40/128" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-des" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\DES 56/56" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-3des" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\Triple DES 168/168" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-md5" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\MD5" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-sha1" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Hashes\SHA" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "disable-null" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Ciphers\\NULL" /f /v Enabled /t REG_DWORD /d 0x00000000',
    "deny-renegotiation-req" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v AllowInsecureRenegoClients /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v AllowInsecureRenegoServers /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v DisableRenegoOnServer /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL" /f /v UseScsvForTls /t REG_DWORD /d 0x00000001',
    "disable-dtls-1.0" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001',
    "disable-dtls-1.1" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.1\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001',
    "enable-dtls-1.3" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" /f /v Enabled /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" /f /v Enabled /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\DTLS 1.3\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000',
    "disable-tls-1.0" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v2.0.50727" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v3.0" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SchUseStrongCrypto /t REG_DWORD /d 0x00000001; reg add "HKLM\SOFTWARE\WOW6432Node\Microsoft\.NETFramework\v4.0.30319" /f /v SystemDefaultTlsVersions /t REG_DWORD /d 0x00000001',
    "disable-tls-1.1" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001',
    "enable-tls-1.3" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f /v Enabled /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f /v Enabled /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000000',
    "disable-sslv2" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001',
    "disable-sslv3" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Server" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f /v Enabled /t REG_DWORD /d 0x00000000; reg add "HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client" /f /v DisabledByDefault /t REG_DWORD /d 0x00000001',
    "disable-admin-shares" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v "AutoShareWks" /t REG_DWORD /d 0 /f',
    "enable-DEP" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoDataExecutionPrevention" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v "DisableHHDEP" /t REG_DWORD /d 0 /f',
    "disable-autoplaynrun" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d 255 /f ; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoAutorun" /t REG_DWORD /d 1 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v "NoAutoplayfornonVolume" /t REG_DWORD /d 1 /f',
    "disable-remote-assist" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowToGetHelp" /t REG_DWORD /d 0 /f; reg add "HKLM\SYSTEM\CurrentControlSet\Control\Remote Assistance" /v "fAllowFullControl" /t REG_DWORD /d 0 /f',
    "disable-lockscreen-cam" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization" /v "NoLockScreenCamera" /t REG_DWORD /d 1 /f',
    "LAN-manager-passhash" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v "NoLMHash" /t REG_DWORD /d 1 /f',
    "disable-priv-install" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer" /v "AlwaysInstallElevated" /t REG_DWORD /d 0 /f',
    "winrm-basic-auth" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Client" /v "AllowBasic" /t REG_DWORD /d 0 /f',
    "Anon-enum-shares" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f',
    "refuse-insecure-auth" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f',
    "enable-SEHOP" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\LSA" /v "RestrictAnonymous" /t REG_DWORD /d 1 /f',
    "Anon-enum-SAM" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\kernel" /v "RestrictAnonymousSAM" /t REG_DWORD /d 1 /f',
    "anon-access-shares" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" /v "RestrictNullSessAccess" /t REG_DWORD /d 1 /f',
    "disable-connectnow" : 'reg add "HKLM\Software\Policies\Microsoft\Windows\WCN\\UI" /v "DisableWcnUi" /t REG_DWORD /d 1 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableFlashConfigRegistrar" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableInBand802DOT11Registrar" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableUPnPRegistrar" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "DisableWPDRegistrar" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WCN\Registrars" /v "EnableRegistrars" /t REG_DWORD /d 0 /f',
    "NTP-pool.ntp.org" : 'w32tm /config /syncfromflags:manual /manualpeerlist:"0.pool.ntp.org 1.pool.ntp.org 2.pool.ntp.org 3.pool.ntp.org"; SC queryex "w32time"|Find "STATE"|Find /v "RUNNING">Nul||(net stop w32time); net start w32time; w32tm /config /update; w32tm /resync',
    "enable-MDAR" : 'powershell -command "Enable-WindowsOptionalFeature -online -FeatureName Windows-Defender-ApplicationGuard"',
    "enable-HVCI" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f; reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "RequirePlatformSecurityFeatures" /t REG_DWORD /d 1 /f; reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "Locked" /t REG_DWORD /d 0 /f; reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Enabled" /t REG_DWORD /d 1 /f; reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity" /v "Locked" /t REG_DWORD /d 0 /f',
    "enable-VBS" : 'reg add "HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard" /v "EnableVirtualizationBasedSecurity" /t REG_DWORD /d 1 /f'
}

Privacy = {
    "folder-access" : 'reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\documentsLibrary" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\picturesLibrary" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\videosLibrary" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\broadFileSystemAccess" /v "Value" /d "Deny" /t REG_SZ /f',
    "cortana-voice-access" : 'reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\\UserPreferenceForAllApps" /v "AgentActivationEnabled" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoice" /t REG_DWORD /d 2 /f; reg add "HKCU\Software\Microsoft\Speech_OneCore\Settings\VoiceActivation\\UserPreferenceForAllApps" /v "AgentActivationOnLockScreenEnabled" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsActivateWithVoiceAboveLock" /t REG_DWORD /d 2 /f',
    "apps-location-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location" /v "Value" /d "Deny" /f; reg add "HKLM\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration" /v "Status" /d "0" /t REG_DWORD /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation" /t REG_DWORD /d 2 /f;reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_UserInControlOfTheseApps" /t REG_MULTI_SZ /f;reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceAllowTheseApps" /t REG_MULTI_SZ /f;reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessLocation_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "app-account-info-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\userAccountInformation" /v "Value" /d "Deny" /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessAccountInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "motion-data-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\activity" /v "Value" /d "Deny" /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMotion_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "phone-access" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessPhone_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "app-sync-deny" : 'reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsSyncWithDevices_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    # optional 
    "camera-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCamera_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    # optional
    "microphone-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMicrophone_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "share-over-upnp" : 'reg add "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /t REG_SZ /v "Value" /d "Deny" /f',
    "diagnostic-data-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appDiagnostics" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsGetDiagnosticInfo_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "contact-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\contacts" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessContacts_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "notification-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\userNotificationListener" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessNotifications_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "call-history-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\phoneCallHistory" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCallHistory_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "calender-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\appointments" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessCalendar_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "email-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\email" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessEmail_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "task-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\\userDataTasks" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessTasks_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "sms-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\chat" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessMessaging_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "bluetooth-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\bluetoothSync" /v "Value" /d "Deny" /t REG_SZ /f',
    "radio-access" : 'reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\radios" /v "Value" /d "Deny" /t REG_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios" /t REG_DWORD /d 2 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_UserInControlOfTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceAllowTheseApps" /t REG_MULTI_SZ /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\AppPrivacy" /v "LetAppsAccessRadios_ForceDenyTheseApps" /t REG_MULTI_SZ /f',
    "webcam-telemetry" : '''reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'DeviceCensus.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f ; schtasks /change /TN "Microsoft\Windows\Device Information\Device" /disable''',
    "compatibility-telemetry" : '''schtasks /change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable ; schtasks /change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable ; schtasks /change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable ; schtasks /change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable ; reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\'CompatTelRunner.exe'" /v "Debugger" /t REG_SZ /d "%windir%\System32\taskkill.exe" /f''',
    "disable-CEIP" : '''reg add "HKLM\Software\Policies\Microsoft\SQMClient\Windows" /v "CEIPEnable" /t REG_DWORD /d "0" /f ; schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /DISABLE ; schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /DISABLE ; schtasks /change /TN "\Microsoft\Windows\Customer Experience Improvement Program\\UsbCeip" /DISABLE''',
    "disable-AIT" : '''reg add "HKLM\Software\Policies\Microsoft\Windows\AppCompat" /v "AITEnable" /t REG_DWORD /d "0" /f''',
    "disable-data-collection" : '''reg add "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /d 0 /t REG_DWORD /f; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v "LimitEnhancedDiagnosticDataWindowsAnalytics" /t REG_DWORD /d 0 /f/; reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" /v "AllowTelemetry" /t REG_DWORD /d 0 /f''',
    "licence-telementry" : '''reg add "HKLM\Software\Policies\Microsoft\Windows NT\CurrentVersion\Software Protection Platform" /v "NoGenTicket" /t "REG_DWORD" /d "1" /f''',
    "disable-error-reporting" : '''reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t REG_DWORD /d "1" /f; reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v "Disabled" /t "REG_DWORD" /d "1" /f; reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultConsent" /t REG_DWORD /d "0" /f; reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting\Consent" /v "DefaultOverrideBehavior" /t REG_DWORD /d "1" /f; reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "DontSendAdditionalData" /t REG_DWORD /d "1" /f; reg add "HKLM\Software\Microsoft\Windows\Windows Error Reporting" /v "LoggingDisabled" /t REG_DWORD /d "1" /f; schtasks /Change /TN "Microsoft\Windows\ErrorDetails\EnableErrorDetailsUpdate" /Disable; schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable; PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wersvc'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"; PowerShell -ExecutionPolicy Unrestricted -Command "$serviceName = 'wercplsupport'; Write-Host "^""Disabling service: `"^""$serviceName`"^""."^""; <# -- 1. Skip if service does not exist #>; $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue; if(!$service) {; Write-Host "^""Service `"^""$serviceName`"^"" could not be not found, no need to disable it."^""; Exit 0; }; <# -- 2. Stop if running #>; if ($service.Status -eq [System.ServiceProcess.ServiceControllerStatus]::Running) {; Write-Host "^""`"^""$serviceName`"^"" is running, stopping it."^""; try {; Stop-Service -Name "^""$serviceName"^"" -Force -ErrorAction Stop; Write-Host "^""Stopped `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Warning "^""Could not stop `"^""$serviceName`"^"", it will be stopped after reboot: $_"^""; }; } else {; Write-Host "^""`"^""$serviceName`"^"" is not running, no need to stop."^""; }; <# -- 3. Skip if already disabled #>; $startupType = $service.StartType <# Does not work before .NET 4.6.1 #>; if(!$startupType) {; $startupType = (Get-WmiObject -Query "^""Select StartMode From Win32_Service Where Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; if(!$startupType) {; $startupType = (Get-WmiObject -Class Win32_Service -Property StartMode -Filter "^""Name='$serviceName'"^"" -ErrorAction Ignore).StartMode; }; }; if($startupType -eq 'Disabled') {; Write-Host "^""$serviceName is already disabled, no further action is needed"^""; }; <# -- 4. Disable service #>; try {; Set-Service -Name "^""$serviceName"^"" -StartupType Disabled -Confirm:$false -ErrorAction Stop; Write-Host "^""Disabled `"^""$serviceName`"^"" successfully."^""; } catch {; Write-Error "^""Could not disable `"^""$serviceName`"^"": $_"^""; }"''',
    "location-access" : '''reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableWindowsLocationProvider" /t REG_DWORD /d "1" /f; reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocationScripting" /t REG_DWORD /d "1" /f''',
    "disable-location" : '''reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors" /v "DisableLocation" /d "1" /t REG_DWORD /f''',
    "disable-bing" : '''reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d 0 /f''',
    "searchbar-websearch" : '''reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v "ConnectedSearchUseWeb" /t REG_DWORD /d 0 /f'''
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
                print("\n[+] Selected Automatic Configurations.")
                flow_check = 1
                break
            elif mode == "use 2" or mode == "use manual":
                print("\n[+] Selected Manual Configurations")
                flow_check = 2
                break
            else:
                print('\nGiven input have some errors...\nTry using "use <mode-number/name>"')

def privacy():
    global flow_check
    global Privacy
    if flow_check == 0:
        print("[-] Select Mode First")
    else:
        if flow_check==1:
            print("\n1 Selected\n")
            ################################
            for x in Privacy:
                actions(Privacy[x])
            #################################
        elif flow_check==2:
            print("\n2 selected")
            print("\nThis feature is under construction")
        else:
            print("First Specify which mode to work with.")

def security():
    global flow_check
    global Security
    if flow_check == 0:
        print("[-] Select Mode First")
    else:
        if flow_check==1:
            print("\n1 Selected")
            ################################
            for x in Security:
               actions(Security[x])
            #################################
        elif flow_check==2:
            print("\n2 selected")
            print("\nThis feature is under construction")
        else:
            print("First Specify which mode to work with.")

def actions(perform):
    out_check = os.system(perform)
    if out_check == 0:
        print('[+] DONE!\n')
    else:
        print('[-] FAILED!\n')


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
            elif console_input == "security":  # For enabling security in Windows
                security()
            else:
                print("Entered input is not a valid command in WindSec")

console()