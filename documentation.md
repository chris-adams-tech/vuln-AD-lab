# Secretcon Active Directory server build

Writeup and Active Directory build by: Chris Adams

LinkedIn: [www.linkedin.com/in/christoph-adams](https://www.linkedin.com/christoph-adams) 

Website: https://chris-adams.notion.site  


---

# A bit about this project

---

This project came about by attending the first Secretcon in Minneapolis, Mn, then getting an opportunity with a team to create the Red/Blue Team village. The initial build was based off of a vulnerable AD ******GitHub lab, originally by **safebuffer** https://github.com/safebuffer/vulnerable-AD. I, by no means take any credit for the scripts written in these documents, I merely put pieces together of something that was already created, with hopes to learn from it and continue to expand on it. With that being said, I hope you learn something and can build this on your own, then expand on it as I will continue to.

Some of the build was based off of work by Joas A Santos. Here is a link to his build: 

> https://www.linkedin.com/feed/update/urn:li:activity:7203009970085195777/
> 

# Tools used in this project

- Active Directory
- KVM/VMware

- Ubuntu22.04 (server)
- Kali Linux

- OpenSSH (optional)
- PowerShell

My home lab set up was originally built on Qemu/KVM then we implemented the actual build into Proxmox.

<aside>
As of right now, this is only including the Active Directory and Wazuh build along with their respective rulesets.

</aside>

<aside>
⚠️ If configuring this in your home network, ensure you are isolating this subnet from the rest of your network with proper bridging/VLANs.

</aside>

# Some good prior knowledge to have

- Networking (changing IP addresses)

- PowerShell (executing commands)

- Setting up virtual machines and/or bridges

---

# Active Directory Set up

---

<aside>
💡 In this implementation, we used Windows Server 2022 server core. It did make it a bit tricky working around server core, but we learned a lot through this initial build. There is a limited set of features, which reduces the complexity but also limits the attack surface. In future use cases, we may have one domain as server core, while replicating the configuration settings from the other domain controller.

</aside>

### Windows Server download

1. First, download Windows server from the Windows website, the Evaluation version. This allows for 180 days of use for the trial license.
    
    https://www.microsoft.com/en-us/evalcenter/download-windows-server-2022
    
    *(some browsers won’t allow you to view the ISO, if that happens, try from a different browser)*
    

### Steps if installing with the GUI desktop experience

1.**Choose Windows Server 2022 Standard Evaluation (Desktop Experience)**

![alt text](C:\Users\errday\Documents\GitHub\vuln-AD-lab\.github\attachments\image.png)

2.**Choose ‘Custom: Install Microsoft Server Operating System’**

![alt text](image-1.png)

1. **Select the ‘Unallocated’ drive**

![alt text](image-2.png)

4.**Change the name of the Computer** 

![alt text](image-3.png)

(Reboot needed)

1. Once the Windows Server is installed, open a PowerShell window as Administrator:
2. Run the command below to add Domain Services role to Server Manager
    
    ```powershell
    PS C:\Users\Administrator> 
    Install-WindowsFeature -Name ad-domain-services -IncludeManagementTools
    ```
    
3. Then, run this script to install Active Directory, be sure to change the domain name before executing
    
    ```powershell
    PS C:\Users\Administrator> 
    Install-ADDSForest -CreateDnsDelegation:$false -DatabasePath "C:\\Windows\\NTDS" -DomainMode "7" -DomainName "insert.domain" -DomainNetbiosName "domain" -ForestMode "7" -InstallDns:$true -LogPath "C:\\Windows\\NTDS" -NoRebootOnCompletion:$false -SysvolPath "C:\\Windows\\SYSVOL" -Force:$true
    ```
    
    `Install-ADDSForest` - creates a new Active Directory forest
    
    `-CreateDnsDelegation` - creates DNS delegation that references new DNS server you install    along with the domain controller
    
    `-DatabasePath` - specifies fully qualified, non-Universal Naming Convention (UNC) path to directory — default is %SYSTEMROOT%\NTDS
    
    `-DomainMode` - specifies domain functional level of first domain in creation of new forest — 7 is Windows Server 2016 or newer
    
    `-DomainName` - specifies fully qualified domain name (FQDN) for root domain in forest
    
    `-DomainNetbiosName` - specifies NetBIOS name value
    
    `-ForestMode` - specifies domain functional level of first domain in creation of new forest — 7 is Windows Server 2016 or newer
    
    `-InstallDns` - indicates cmdlet installs and configures DNS Server service for new forest
    
    `-LogPath` - specifies fully qualified, non-UNC path to a directory where log file for this operation is written
    
    `-NoRebootOnCompletion` - indicates cmdlet does not reboot upon completion
    
    `-SysvolPath` - specifies fully qualified, non-UNC path to a directory where Sysvol file is written
    
    `-Force` - forces command to run without asking for user confirmation
    
4. The server will then reboot and the next login should be with the domain level domain\user.

<aside>
💡 This could also be done through an SSH connection and just run the scripts via PuTTy or a terminal window. I did not because OpenSSH does not play nicely from a Linux KVM to Windows machine.

</aside>

---

## Sysmon Installation

---

<aside>
💡 In this setup, we used the *Swift on Security* configuration file for high-quality event tracing. Though this doesn’t include everything needed or necessarily cover all types of attacks, it is a great starting point. There is another one linked in that GitHub page that has some great rulesets that could increase visibility.

</aside>

Check out the ruleset here: https://github.com/SwiftOnSecurity/sysmon-config 

![alt text](image-4.png)

1. Download the raw xml file in the files below the README.md
    
  ![alt text](image-5.png)
    

1. Now, download Sysmon from Windows
    
    https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon
    
   ![alt text](image-6.png)
    
2. Extract the packages from the Sysmon download

1. Move the `sysmonconfig-export.xml` file into the Sysmon folder that was just extracted

1. Open PowerShell as administrator and move into the Sysmon folder
    
    ```powershell
    PS C:\Users\*****\Downloads\Sysmon> .\sysmon64.exe -accepteula -i sysmonconfig-export.xml
    ```
    
    `accepteula` - accepts End User License Agreement
    
    `-i` - installs service and driver along with configuration file
    

### Desktop Instructions

### Enable PowerShell Module Logging and other GPO settings

<aside>
💡 The PowerShell Module logging, along with other logging settings, will allow us to capture the full output of the scripts that are being run. Of course, it will be captured on the local machine, then forwarded via Powershell logs to Wazuh.

</aside>

![alt text](image-7.png)

![alt text](image-8.png)

![alt text](image-9.png)

![alt text](image-10.png)

<aside>
ℹ️ This will create a text file of the Powershell transcript to verify that the logs are being received in the intended manner.

</aside>

---

# Download the PowerShell script

---

1. To download directly from GitHub
    
    ```powershell
    PS C:\Users\Administrator> 
    wget https://raw.githubusercontent.com/WaterExecution/vulnerable-AD-plus/master/vulnadplus.ps1 -o vulnadplus.ps1
    ```
    
    `-o` - saves the output file to vulnadplus.ps1
    
    In the screenshot below are the types of attacks that can be implemented in this lab environment. These may be adjusted by going into the `vulnadplus.ps1` script BEFORE running to adjust to your purposes.
    
   ![alt text](image-11.png)
    
2. Open the PowerShell file with notepad to adjust the domain name and number of desired users
    
    ![alt text](image-12.png)
    

<aside>
💡 Changing the domain name is a crucial step! I also do not recommend using 100 users to start out. Keep it simple at first, then expand from there.

</aside>

1. Before running the script, we want to ensure there is no connectivity to the internet if not done so already and the DNS is set to it’s own IP address, or loopback `127.0.0.1`. 
    
    **Set your network on this device to ‘isolated’ so it is disconnected from NAT or anything outside of the subnet.**
    
2. Open PowerShell and run the edited PowerShell script
    
    ```powershell
    PS C:\Users\Administrator> 
    Import-Module .\vulnadplus.ps1
    ```
    
    The output will look like below:
    
    <aside>
    ℹ️ The usernames are randomized fyi
    
    </aside>
    
    ![vulnusers.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/dff01248-f3b8-434c-8ab8-628d8431c26a/55f29125-b9ec-428b-960a-16dbf6de6190/vulnusers.png)
    
    ![vulnusers 2.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/dff01248-f3b8-434c-8ab8-628d8431c26a/680968c8-9124-4de2-be19-5a6d2d1cd68f/vulnusers_2.png)
    
    ![badacl.png](https://prod-files-secure.s3.us-west-2.amazonaws.com/dff01248-f3b8-434c-8ab8-628d8431c26a/aca2e1aa-cc54-4f53-bca2-939f67ef6072/badacl.png)
    

<aside>
💡 Another option would be to download the files, scripts, then put on a USB drive and redirect the USB drive to the virtual machine. Alternatively, this could be done via Samba/SMB share.

</aside>

---

# Install Wazuh

---

<aside>
💡 *Wazuh* is a open-source security platform that provides unified XDR and SIEM protection for endpoints and cloud workloads.

</aside>

Three main components to *Wazuh*:

1. *Wazuh* server
2. *Wazuh* indexer
3. *Wazuh* dashboard

Hardware requirements:

| **Agents** | **CPU** | **RAM** | **Storage (90 days)** |
| --- | --- | --- | --- |
| **1–25** | 4 vCPU | 8 GiB | 50 GB |
| **25–50** | 8 vCPU | 8 GiB | 100 GB |
| **50–100** | 8 vCPU | 8 GiB | 200 GB |

Operating System

| Amazon Linux 2 | CentOS 7, 8 |
| --- | --- |
| Red Hat Enterprise Linux 7, 8, 9 | Ubuntu 16.04, 18.04, 20.04, 22.04 |

Browser compatibibility:

- Chrome 95 or later
- Firefox 93 or later
- Safari 13.7 or later

## Installing Wazuh dashboard

<aside>
💡 Before beginning, a virtual machine with an operating system from above will need to be booted up. In this project, we used *Ubuntu 22.04* but any of the mentioned will be okay, as long as the hardware requirements are met (There were some issues with using low RAM).

</aside>

1. Begin by connecting or opening an SSH connection into your virtual machine.

<aside>
💡 For password-less SSH connection, on your host machine run `ssh-keygen -t ed25519` to generate an SSH key. Then, run `ssh-copy-id <vm-user>@<vm-ip>`. There should be a prompt to enter your VM user password. Verify that you are able to connect, then you are able to run the commands from your host machine via an SSH connection.

</aside>

Wazuh can easily installed by using the installation assistant by using the script below:

```bash
curl -sO https://packages.wazuh.com/4.8/wazuh-install.sh && sudo bash ./wazuh-install.sh -a
```

![alt text](image-13.png)

The output will look similar to below:

1. Once finished, the password will be displayed in the output.

![alt text](image-14.png)

1. To access the web interface, go to `https://<wazuh-dashboard-ip>` on your host machine, using the credentials from the output in the last step.

There will be a notice that “Your connection is not private” and is expected. Click **Advanced** and **Proceed to *<wazuh-ip>* (unsafe)**

![alt text](image-15.png)

Then, a login screen will appear, where you can enter in the credentials **“admin**” and the password that was generated with the installation.

<aside>
This password can be changed but requires a few steps to sync the API and other backend passwords.

</aside>

![alt text](image-16.png)

After entering the correct credentials, there will be some checks to ensure that everything was configured correctly on the backend

![alt text](image-17.png)

Once connected, you should have landed on a page like this:

![alt text](image-18.png)

1. Once on the web interface, add an agent from the Overview page on the Wazuh dashboard
    
    Click the “Add agent” 
    
    ![alt text](image-19.png)
    
    ![alt text](image-20.png)
    

*This will allow you to generate a agent deploy script for your Active Directory domain controller* 

The script will look something like this

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.8.0-1.msi -OutFile ${env.tmp}\wazuh-agent; msiexec.exe /i ${env.tmp}\wazuh-agent /q WAZUH_MANAGER='<manager-ip>' WAZUH_AGENT_GROUP='<group-name>' WAZUH_AGENT_NAME='<agent-name>' 
```

<aside>
ℹ️ This may be tricky to copy/paste depending on the type of hardware you are using. I use *spice-vdagent* for my Linux machine.

</aside>

### Now, shift back to the domain controller with Active Directory

1. Verify there were no errors, then run `NET START WazuhSvc` (this will start the Wazuh service)
2. After a few moments, a *Disconnected* agent should appear in the Wazuh dashboard
3. Shortly after, it should show as *Connected.*
4. On initial boot, if the settings are not changed, there will be a host of logs from the CIS benchmark scan. *These can be disabled in the* `ossec.conf` *file.* 

<aside>
💡 In order for alerts to be sent to Wazuh, some configuration in the `ossec.conf` file is needed.

</aside>

1. To configure the Sysmon configuration for the agent, go to `C:\'Program Files (x86)'\ossec-agent-ossec.conf` (can be opened in notepad)

1. Add these two sections (Event Channels) to the configuration file then save
    
    ```xml
      <localfile>    
        <location>Microsoft-Windows-Sysmon/Operational</location>
        <log_format>eventchannel</log_format>
      </localfile>
    
      <localfile>    
        <location>Microsoft-Windows-PowerShell/Operational</location>
        <log_format>eventchannel</log_format>
      </localfile>
    ```
    
    <aside>
    💡 Additional event channels can also be added by using the format below, :
    
    ```
    <localfile>
      <location>Microsoft-Windows-PrintService/Operational</location>
      <log_format>eventchannel</log_format>
    </localfile>
    ```
    
    </aside>
    
    ## Options for configuring Windows Event Channels in Wazuh
    
    | **Source** | **Channel name** | **Provider name** | **Description** |
    | --- | --- | --- | --- |
    | **Application** | Application | Any | This channel collects events related to system application management and is one of the main Windows administrative channels along with Security, and System. |
    | **Security** | Security | Any | This channel gathers information related to user and group creation, login, logoff, and audit policy modifications. |
    | **System** | System | Any | The System channel collects events associated with kernel and service control. |
    | **Sysmon** | Microsoft-Windows-Sysmon/Operational | Microsoft-Windows-Sysmon | Sysmon monitors system activity such as process creation and termination, network connections, and file changes. |
    | **Windows Defender** | Microsoft-Windows-Windows Defender/Operational | Microsoft-Windows-Windows Defender | The Windows Defender log shows information about the scans passed, malware detection, and actions taken against them. |
    | **McAfee** | Application | McLogEvent | This source shows McAfee scan results, virus detection, and actions taken against them. |
    | **EventLog** | System | Eventlog | This source retrieves information about audit and Windows logs. |
    | **Microsoft Security Essentials** | System | Microsoft Antimalware | This source gives information about real-time protection for the system, malware detection scans, and changes in antivirus settings. |
    | **Remote Access** | File Replication Service | Any | Other channels (they are grouped in a generic Windows rule file). |
    | **Terminal Services** | Microsoft-Windows-TerminalServices-RemoteConnectionManager |  |  |
    | **Powershell** | Microsoft-Windows-PowerShell/Operational | Microsoft-Windows-PowerShell | This channel collects and audits PowerShell activity. |
    
    Additionally, the logging level can be adjusted. It will only send alerts higher than configured.
    
    ```xml
    <ossec_config>  
      <syslog_output>
        <level>9</level> # Alert level can be adjusted
        <server>192.168.10.1</server> # If level higher than 9, also sent here 
      </syslog_output>
      
      <syslog_output>
        <server>192.168.10.2</server> # All alerts are sent here
      </syslog_output>
    </ossec_config>
    ```
    
    If you would like to disable the CIS benchmark scans, change the field in the config
    
    ```xml
      <!-- CIS policies evaluation -->
      <wodle name="cis-cat">
        <disabled>yes</disabled>
        <timeout>1800</timeout>
        <interval>1d</interval>
        <scan-on-start>no</scan-on-start>
    ```
    
    There are many other settings that can be adjusted in this file that we will not get into here.
    
    <aside>
    ℹ️ When changing any of the files, restart the service for the changes to take effect.
    `systemctl restart wazuh-manager`
    
    </aside>
    
2. If you are having any communication issues with the agent, check the agent configuration file at `C:\'Program Files (x86)'\ossec-agent-ossec.conf` to verify the Wazuh server IP address.

```xml
    <server>
      <address>'wazuh-server-ip'</address>
      <port>1514</port>
      <protocol>tcp</protocol>
    </server>
```

*This ensures communication between the agent and server*

# Configuring the alerts on Wazuh server

<aside>
💡 In addition to the Sysmon config, the Wazuh server must be configured in order to create alerts on the dashboard. This is where you can use different types of detection logic depending on the data that is captured.

Within these rule sets, the field names that are captured from the logs can be used to map event codes and other telemetry to alert levels and your own rule descriptions.

</aside>

Below is the ruleset that was used in this setup.

```xml
<group name="security_event, windows,">
 
  <!-- This rule detects DCSync attacks using windows security event on the domain controller -->
  <rule id="110001" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}|{19195a5b-6da0-11d0-afd3-00c04fd930c9}</field>
    <options>no_full_log</options>
    <description>Directory Service Access. Possible DCSync attack</description>
  </rule>
 
 <!-- This rule ignores Directory Service Access originating from machine accounts containing $ -->
 <rule id="110009" level="0">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4662$</field>
    <field name="win.eventdata.properties" type="pcre2">{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}|{19195a5b-6da0-11d0-afd3-00c04fd930c9}</field>
    <field name="win.eventdata.SubjectUserName" type="pcre2">\$$</field>
    <options>no_full_log</options>
    <description>Ignore all Directory Service Access that is originated from a machine account containing $</description>
  </rule>
 
  <!-- This rule detects Keberoasting attacks using windows security event on the domain controller -->
  <rule id="110002" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4769$</field>
    <field name="win.eventdata.TicketOptions" type="pcre2">0x40810000</field>
    <field name="win.eventdata.TicketEncryptionType" type="pcre2">0x17</field>
    <options>no_full_log</options>
    <description>Possible Keberoasting attack</description>
  </rule>
 
  <!-- This rule detects Golden Ticket attacks using windows security events on the domain controller -->
  <rule id="110003" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.LogonGuid" type="pcre2">{00000000-0000-0000-0000-000000000000}</field>
    <field name="win.eventdata.logonType" type="pcre2">3</field>
    <options>no_full_log</options>
    <description>Possible Golden Ticket attack</description>
  </rule>
 
  <!-- This rule detects when PsExec is launched remotely to perform lateral movement within the domain. The rule uses Sysmon events collected from the domain controller. -->
  <rule id="110004" level="12">
    <if_sid>61600</if_sid>
    <field name="win.system.eventID" type="pcre2">17|18</field>
    <field name="win.eventdata.PipeName" type="pcre2">\\PSEXESVC</field>
    <options>no_full_log</options>
    <description>PsExec service launched for possible lateral movement within the domain</description>
  </rule>
  <!-- This rule detects NTDS.dit file extraction using a sysmon event captured on the domain controller -->
  <rule id="110006" level="12">
    <if_group>sysmon_event1</if_group>
    <field name="win.eventdata.commandLine" type="pcre2">NTDSUTIL</field>
    <description>Possible NTDS.dit file extraction using ntdsutil.exe</description>
  </rule>
  <!-- This rule detects Pass-the-ash (PtH) attacks using windows security event 4624 on the compromised endpoint -->
  <rule id="110007" level="12">
    <if_sid>60103</if_sid>
    <field name="win.system.eventID">^4624$</field>
    <field name="win.eventdata.LogonProcessName" type="pcre2">seclogo</field>
    <field name="win.eventdata.LogonType" type="pcre2">9</field>
    <field name="win.eventdata.AuthenticationPackageName" type="pcre2">Negotiate</field>
    <field name="win.eventdata.LogonGuid" type="pcre2">{00000000-0000-0000-0000-000000000000}</field>
    <options>no_full_log</options>
    <description>Possible Pass the hash attack</description>
  </rule>
  
  <!-- This rule detects credential dumping when the command sekurlsa::logonpasswords is run on mimikatz -->
  <rule id="110008" level="12">
    <if_sid>61612</if_sid>
    <field name="win.eventdata.TargetImage" type="pcre2">(?i)\\\\system32\\\\lsass.exe</field>
    <field name="win.eventdata.GrantedAccess" type="pcre2">(?i)0x1010</field>
    <description>Possible credential dumping using mimikatz</description>
  </rule>

</group>
```

I had some additional rulesets implemented, then unfortunately had to snapshot and did not get these ones back on the machine

```xml
<Sysmon schemaversion="4.30">
   <EventFiltering>
      <RuleGroup name="" groupRelation="or">
         <ProcessAccess onmatch="include">
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\csrss.exe</TargetImage> <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1F1FFF</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\wininit.exe</TargetImage> <!--Mitre T1098-->        <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1F1FFF</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\winlogon.exe</TargetImage> <!--Mitre T1098-->       <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1F1FFF</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\services.exe</TargetImage> <!--Mitre T1098-->       <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1F1FFF</GrantedAccess>
            <!-- In some environments this causes HIGH CPU usage by sysmon, remove this module when that occurs -->
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage> <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1FFFFF</GrantedAccess>          <!--Expect EDRs/AVs to also trigger this-->
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage> <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1F1FFF</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage> <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x1010</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="is">C:\Windows\system32\lsass.exe</TargetImage> <!--Mitre T1098-->          <!--Mitre T1550.002-->          <!--Mitre T1003-->          <!-- depending on what you're running on your host, this might be noisy-->
               <GrantedAccess>0x143A</GrantedAccess>
            </Rule>
            <Rule groupRelation="and">
               <TargetImage name="technique_id=T1003,technique_name=Credential Dumping" condition="image">lsass.exe</TargetImage>          <!--https://pentestlab.blog/2018/05/15/lateral-movement-winrm/-->
               <SourceImage name="technique_id=T1003,technique_name=Credential Dumping" condition="image">wsmprovhost.exe</SourceImage>
            <Rule groupRelation="and" name="technique_id=T1055,technique_name=Process Injection">
               <SourceImage condition="contains all">C:\Program Files;\Microsoft Office\Root\Office</SourceImage>
               <CallTrace condition="contains">\Microsoft Shared\VBA</CallTrace>
            </Rule>
            <Rule groupRelation="and"><!-- https://medium.com/falconforce/falconfriday-direct-system-calls-and-cobalt-strike-bofs-0xff14-741fa8e1bdd6 -->
               <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\ntdll.dll</CallTrace>
               <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\win32u.dll</CallTrace>
               <CallTrace name="technique_id=T1055,technique_name=Process Injection" condition="not begin with">C:\Windows\SYSTEM32\wow64win.dll</CallTrace>
            </Rule>
         </ProcessAccess>
      </RuleGroup>
   </EventFiltering>
</Sysmon>

<Sysmon schemaversion="4.30">
  <EventFiltering>
    <RuleGroup name="" groupRelation="or">
      <RegistryEvent onmatch="include">
        <TargetObject name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="contains">SYSTEM\CurrentControlSet\Control\CrashControl</TargetObject><!--MDE--><!-- Win32_OSRecoveryConfiguration class C2 maps to a change in values within the following key: -->
        <TargetObject name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\autologger\senseauditlogger</TargetObject><!--MDE-->
        <TargetObject name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\autologger\senseeventlog</TargetObject><!--MDE-->
        <TargetObject name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\EtwMaxLoggers</TargetObject><!--MDE-->
        <TargetObject name="technique_id=T1047,technique_name=Windows Management Instrumentation" condition="contains all">HKLM\SYSTEM\;Control\WMI\Security</TargetObject><!--MDE-->
      </RegistryEvent>
    </RuleGroup>
  </EventFiltering>
</Sysmon>

```

# User and Agent Management

## Creating users in Wazuh dashboard

<aside>
💡 If you would like to limit access, or change to a user account using a different password, then steps below can be followed

</aside>

1. Go to the ‘hamburger’ in the top left corner
2. Scroll down to the **Dashboard management** > **Security**
3. 

![alt text](image-21.png)

## Removing an agent from the Wazuh manager

![alt text](image-22.png)