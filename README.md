<img width="975" height="752" alt="image" src="https://github.com/user-attachments/assets/59b2f652-9203-475e-b71c-d508fcafac37" /><img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/f8f2f1d5-c2bd-4d27-98d0-9a727876d09e" />## Cybersecurity Home Lab Setup and Threat Telemetry Analysis

### Objective

The objective of this project was to architect and deploy a robust, virtualized home lab environment to serve as a secure, segmented sandbox for advanced cybersecurity practice. The core goal was to install and configure a **Type-2 hypervisor** to host a current target machine (**Windows 11 Pro**) and an attacker machine (**Kali Linux**), while specifically focusing on **Detection Engineering** by:

* **Isolating the lab network** completely using internal virtual networking to prevent host machine compromise.
* Deploying an advanced logging agent (**Sysmon**) and a **Security Information and Event Management (SIEM)** platform (**Splunk**) to collect high-fidelity security telemetry.
* Simulating basic attacker Tactics, Techniques, and Procedures (**TTPs**) to generate relevant log data and practice **analyzing the full attack chain** within the SIEM environment.

### Skills Learned

**I. Infrastructure & Systems Administration:**
* **Virtualization Management:** Deployed and configured **Oracle VirtualBox** to host multiple guest operating systems, effectively managing hypervisor settings and resource allocation.
* **OS Provisioning & Customization:** Performed manual installation of the **Windows 11 Pro ISO** and imported pre-configured virtual appliances (**Kali Linux**).
* **Low-Level System Configuration:** Successfully bypassed mandatory Windows 11 hardware requirements (**TPM, Secure Boot**) within the VM environment by executing commands and/or making **Registry modifications** during the setup process.
* **File Integrity Verification:** Utilized cryptographic hashing (**SHA-256**) via **Windows PowerShell** (`Get-FileHash`) to verify the integrity and authenticity of software installers before execution.
* **Snapshot & Disaster Recovery:** Implemented **snapshot strategies** to create "known good" baselines, allowing for rapid system restoration after destructive testing or malware execution.

**II. Network Architecture & Isolation (Sandboxing):**
* **Network Segmentation:** Configured VM network adapters to use **Internal Network** mode (VirtualBox) or **LAN Segment** (VMware), ensuring complete network isolation from the host and production network.
* **Static IP Configuration:** Performed manual **static IPv4 address assignment** on both Windows and Kali Linux guests, providing reliable, controlled communication exclusively between the lab machines.

**III. Detection Engineering (Blue Team):**
* **Endpoint Logging:** Installed and configured **Sysmon** on the Windows target machine to generate rich security telemetry (Process Creation, Network Connections, etc.).
* **SIEM Administration:** Deployed and configured **Splunk Enterprise** to ingest Sysmon event logs by setting up appropriate indices and using the **Splunk Add-on for Sysmon**.
* **Threat Analysis & Querying:** Performed log analysis via **Splunk Search Processing Language (SPL)** to trace the simulated attack chain, identifying malware process execution, outbound connections, and post-exploitation commands.

**IV. Threat Simulation (Red Team):**
* **Reconnaissance:** Employed **nmap** for basic network service identification and port scanning against the target system.
* **Exploitation Tooling:** Utilized **msfvenom** to generate a reverse TCP shell payload and **Metasploit Framework (msfconsole)** to set up a listening handler to catch the shell.
* **Delivery Simulation:** Used a **Python HTTP server** to simulate a basic delivery mechanism for the malware payload.

### Tools Used

**Virtualization Stack:**
* **Oracle VirtualBox 7.0** (Type-2 Hypervisor)
* **Windows 11 Pro** (Target OS)
* **Kali Linux** (Attacker OS)

**SIEM & Logging:**
* **Splunk Enterprise** (SIEM Platform)
* **Sysmon** (Windows Endpoint Logger)
* **Splunk Add-on for Sysmon** (Log Parsing)

**Offensive Tools:**
* **nmap** (Network Scanner)
* **msfvenom** (Payload Generation)
* **Metasploit Framework (msfconsole)** (Handler/Listener)

**Core Utilities:**
* **Windows PowerShell** (`Get-FileHash`, `ipconfig`)
* **Windows Registry Editor (regedit)**
* **7-Zip** (File Archiving)
* **Python 3** (`http.server` module)

### Steps

**Diagram**
<img width="975" height="413" alt="image" src="https://github.com/user-attachments/assets/f02ac034-e5a0-4291-92e1-eb2544aa6c44" />

#### Directory 

1. [Installing VirtualBox](#installing-virtualbox)
2. [Installing Windows ISO Image](#installing-windows-iso-image)
3. [Installing 7-Zip](#installing-7-zip)
4. [Installing Kali Linux VM](#installing-kali-linux-vm)
5. [Importing Windows 11 ISO to VirtualBox](#importing-windows-11-iso-to-virtualbox)
6. [Running Windows Without a Microsoft Account](#running-windows-without-a-microsoft-account)
7. [Import Kali Linux to VirtualBox](#import-kali-linux-to-virtualbox)
8. [Creating Snapshots to revert to baseline config](#creating-snapshots-to-revert-to-baseline-config)
9. [Configuring VMs Based On Use Case Scenario](#configuring-vms-based-on-use-case-scenario)
10. [Scenario 1: Testing Tools That Require Internet Connectivity](#scenario-1-testing-tools-that-require-internet-connectivity)
11. [Scenario 2: Analyzing Malware Recommended Settings](#scenario-2:-analyzing-malware-recommended-settings)

#### Installing VirtualBox
Step 1: Head to https://www.virtualbox.org/wiki/Downloads and click download. 
<img width="975" height="731" alt="image" src="https://github.com/user-attachments/assets/30ad990f-474a-4f8a-911a-c4c6dcccae9b" />
Step 1.2: Choose the operating system you are using… in my case Windows. 
<img width="975" height="675" alt="image" src="https://github.com/user-attachments/assets/29b9f614-47a0-4d66-87fa-3f8cc50b1d6d" />
Step 2.1: Compare Hash values to verify integrity of installer. 
<img width="975" height="906" alt="image" src="https://github.com/user-attachments/assets/0dc3caff-3d42-4949-b1be-21040c2b9d4d" />
Step 2.2: Find the VirtualBox version of what you downloaded inside the checksum list. In my case “VirtualBox-7.2.4-170995-Win.exe”  
<img width="975" height="423" alt="image" src="https://github.com/user-attachments/assets/7778b3fd-9d16-41e5-94cf-718ea70ea7c3" />
Step 2.3: Go to where you downloaded the file > Right Click > Then click “Open in Terminal”  
<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/c5546b68-4e84-4dda-a20a-0994121d368f" />

Step2.4: This will open up powershell and in powershell type command.
```PowerShell
Get-FileHash .\VirtualBox-7.2.4-170995-Win.exe
```
Then press enter.
Note: “VirtualBox-7.2.4-170995-Win.exe” is my file name yours might be different
<img width="975" height="542" alt="image" src="https://github.com/user-attachments/assets/4301930f-691c-4e6b-a3e2-8b96c00bfdf9" />
Step 2.5: Double click the generated hash to copy it  
<img width="975" height="548" alt="image" src="https://github.com/user-attachments/assets/9429e57f-56ac-45e3-af4d-0a0e7e07520c" />
Step 2.6: Return to virtualbox checksum list > do ctrl+F > paste in the hash value in powershell from the last step  
<img width="975" height="938" alt="image" src="https://github.com/user-attachments/assets/905c2298-3ce4-41ad-81ec-7a778e6c4cf6" />
Step 2.7: If the same hash value shows the file is not tampered with thus verifying integrity.

Step 3: Initialize installation.
<img width="767" height="610" alt="image" src="https://github.com/user-attachments/assets/f0967515-9544-43e2-b3ff-ebc1529ba954" />
<img width="769" height="613" alt="image" src="https://github.com/user-attachments/assets/c065808c-3cd3-4a96-b56b-e2b2510c0040" />
<img width="760" height="617" alt="image" src="https://github.com/user-attachments/assets/d7024a5f-06f3-4edb-9d51-b431db0c4800" />
<img width="754" height="623" alt="image" src="https://github.com/user-attachments/assets/44e71615-cdd6-4a82-adca-907e88b25493" />
<img width="756" height="617" alt="image" src="https://github.com/user-attachments/assets/4163a520-fcd2-4578-b17a-6e0103c080f1" />
<img width="752" height="608" alt="image" src="https://github.com/user-attachments/assets/0eed9395-273f-411f-9414-bb96b74ead8e" />
<img width="763" height="623" alt="image" src="https://github.com/user-attachments/assets/3dc30d93-e60b-494e-b9d1-e113f12c450d" />
<img width="767" height="617" alt="image" src="https://github.com/user-attachments/assets/5a089bcf-9387-4acf-bbad-c9db8776268c" />

#### Installing Windows ISO Image
Step 1: Go to https://www.microsoft.com/en-us/software-download/windows11 > Create Windows 11 Installation Media > Download 
<img width="975" height="898" alt="image" src="https://github.com/user-attachments/assets/dddd49da-5f62-4c78-868a-f4366c5b4519" />
Step 2: Initialize Installer 
<img width="975" height="767" alt="image" src="https://github.com/user-attachments/assets/0c49929c-509a-4efc-98cd-e65cf9183e6c" />
<img width="975" height="788" alt="image" src="https://github.com/user-attachments/assets/5fdaa612-c0b0-41a4-b89e-deb25b913b94" />
<img width="975" height="785" alt="image" src="https://github.com/user-attachments/assets/187242aa-b592-4651-a91c-a1d7aaf34c86" />
<img width="975" height="785" alt="image" src="https://github.com/user-attachments/assets/499f610f-0800-47c1-9e7b-6a96217afbd4" />

#### Installing 7-Zip
Step 1: go to https://www.7-zip.org/ > Choose appropriate  bit type that corresponds to your system (eg. 64-bit vs 32-bit) .
<img width="860" height="642" alt="image" src="https://github.com/user-attachments/assets/7dbeb4f8-4227-4e60-a88e-51e42da40fd7" />
<img width="494" height="342" alt="image" src="https://github.com/user-attachments/assets/d7192cb8-6eff-4a8a-b724-3bf29f3b2227" />
Step 2: Initialize Installer 
<img width="494" height="371" alt="image" src="https://github.com/user-attachments/assets/063d9c23-662d-4371-875a-2a333cc8a7ea" />

#### Installing Kali Linux VM
Step 1: Go to https://www.kali.org/get-kali/#kali-virtual-machines > VirtualBox Download  
<img width="975" height="948" alt="image" src="https://github.com/user-attachments/assets/09ae20f8-edf6-45a2-89a6-280c4a3b1be7" />
Step 2: Once installed right click installed file, more options > 7zip, Extract File here        
<img width="975" height="683" alt="image" src="https://github.com/user-attachments/assets/fbec7677-6301-45cf-a49c-028d092c7bc3" />
<img width="975" height="685" alt="image" src="https://github.com/user-attachments/assets/09738814-85b0-41da-bf30-587be760a5a6" />
<img width="975" height="623" alt="image" src="https://github.com/user-attachments/assets/c210bdce-0ea1-454f-bece-c5d44bc47028" />
<img width="867" height="554" alt="image" src="https://github.com/user-attachments/assets/1097f040-48e4-4cd4-8dcf-428bd84e4447" />

#### Importing Windows 11 ISO to VirtualBox
Step 1: Run VirtualBox
Step 2: Click New  
<img width="975" height="767" alt="image" src="https://github.com/user-attachments/assets/37fef640-7a45-481a-a892-ca3bfdcbb8fc" />
Step 3: Name VM whatever you want, Pick a Folder location to Place it In, ISO Image = “Windows.ISO” that we created earlier  
<img width="975" height="496" alt="image" src="https://github.com/user-attachments/assets/413d3cc1-20eb-4817-9b05-1e01c7960040" />
Step 4: Allocate Necessary system resources, Base Memory = 4096mb, CPU = 1, Disk Size = 20Gb    
<img width="975" height="513" alt="image" src="https://github.com/user-attachments/assets/5dc8d3d2-dfe5-4da0-8ec5-988cfb652af5" />
<img width="975" height="523" alt="image" src="https://github.com/user-attachments/assets/51610c74-3798-4976-95c1-11394a4ee77c" />
Step 5: Power on Win 11 VM  
<img width="975" height="765" alt="image" src="https://github.com/user-attachments/assets/b7ef1b40-9fc6-4527-b554-d250ffd092b0" />
Step 6: Initialize Windows 11 Installer
<img width="975" height="790" alt="image" src="https://github.com/user-attachments/assets/2523d1a6-2121-49c9-8e37-d6c77e36f7df" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/3c132ee5-d39b-435f-ada4-2380debc2c75" />
<img width="975" height="823" alt="image" src="https://github.com/user-attachments/assets/d2bcfcbc-4a4d-4983-8c66-108004abf530" />
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/9edf9877-9612-467d-ba25-7ee1a7b11c7c" />
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/58ec67ae-d5bd-4cc5-bd1e-63880fee7d80" />
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/1188c752-61bc-49f2-81cd-c8b6c6194418" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/eef81466-6bec-4f9d-9f0f-c96776e8e452" />
Step 6.1: If you get this screen we have to bypass requirements safely via a VM
Step 6.2: press Shift + F10 > Type “regedit”  
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/214aaba4-bef1-4bab-84dd-471832547fe1" />
Step 6.3: Navigate to HKEY_LOCAL_MACHINE\SYSTEM\Setup 
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/3ce17dea-13c7-4d5d-8539-7dd760e80cd3" />
Step 6.4: Right Click “Setup” Folder > New  > Key > Name = “LabConfig”  
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/c6620e0b-f1e6-4e0f-ab68-7150f4d215c7" />
Step 6.5: On the right > Right click > new > Create 4 DWORD (32-bit) Value 
<img width="975" height="917" alt="image" src="https://github.com/user-attachments/assets/e685d482-bbbf-4d3d-be97-42f07e9a5506" />
Step 6.6: Name them BypassTPMCheck = 1, BypassRAMCheck = 1, BypassSecureBootCheck = 1, BypassCPUCheck = 1   
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/2338daab-0a54-4bf2-bf68-a36d86b9484d" />
<img width="975" height="960" alt="image" src="https://github.com/user-attachments/assets/5f8e5abc-592e-47e5-9721-24b2494428ec" />
<img width="975" height="827" alt="image" src="https://github.com/user-attachments/assets/7beb6b74-c201-4afc-9677-f826547d5cdf" />
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/ca00e09f-c783-4c34-b836-52fbe5373c69" />
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/974ef8f1-f814-47e5-be14-243b41f0d884" />
Step 6.7: Try installing Windows 11 Pro again    
<img width="975" height="779" alt="image" src="https://github.com/user-attachments/assets/917b1298-07dd-4909-8926-d4be40264708" />
<img width="975" height="746" alt="image" src="https://github.com/user-attachments/assets/1ad0b2f5-cb03-46d4-b493-de579747c24b" />
<img width="975" height="773" alt="image" src="https://github.com/user-attachments/assets/60dd8463-e50f-4c83-b5af-843c4ebaa921" />
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/890efd47-6b7f-4cdd-9fe5-03da76271d35" />
#### Running Windows Without a Microsoft Account
Step 1 After you reach this screen unplug network connection 
<img width="975" height="867" alt="image" src="https://github.com/user-attachments/assets/fc844667-1c28-44bb-bba5-f221bf789722" />
Step 2 on bottom right > Right Click Network Icon > Network Settings 
<img width="975" height="848" alt="image" src="https://github.com/user-attachments/assets/44512fcb-dc48-4e1f-9253-70b00b55e1bb" />
Step 3: Attach to from “Nat” to “Not Attached”  
<img width="975" height="677" alt="image" src="https://github.com/user-attachments/assets/07ffa0c7-85e3-4d65-b158-fdf937301dbe" />
Step 4: Restart VM and go back to Setup page
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/56820fdd-a82e-4282-baa0-856c522051ea" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/da1fba70-fb4e-4d8d-a7a5-734fc99ee755" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/ff053dad-3843-49aa-87de-73077f2d1135" />
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/333da4ea-ec6f-43a4-b79b-9db2d3fd15a5" />
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/5c291928-e49f-4bec-972f-9379950b7e84" />
<img width="965" height="808" alt="image" src="https://github.com/user-attachments/assets/b15f1d46-ddbd-4ee9-8601-aeeba65630d7" />
<img width="975" height="831" alt="image" src="https://github.com/user-attachments/assets/02194205-f806-4e4e-b95f-a7167a54f460" />
<img width="975" height="823" alt="image" src="https://github.com/user-attachments/assets/6bb1ce3b-1903-4b0b-9d8a-286eac43c8e4" />
<img width="975" height="827" alt="image" src="https://github.com/user-attachments/assets/00a75fc3-1458-4e90-8301-31727946d6dc" />
<img width="975" height="808" alt="image" src="https://github.com/user-attachments/assets/087a72f0-5bbd-4a6f-be88-288ff52ef919" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/6f9a13ef-8cc9-4b6b-b59c-2401504000b7" />

#### Import Kali Linux to VirtualBox
Step 1: Navigate to the folder where you extracted the Kali Linux zip 
<img width="975" height="392" alt="image" src="https://github.com/user-attachments/assets/6f02f73b-2d98-408d-ade2-432e32384fef" />

Step 2: Double  click on the folder  Double click the “.vbox” extension 
<img width="975" height="548" alt="image" src="https://github.com/user-attachments/assets/50cd27d7-4210-4f32-a5b1-8fee9cd7ee8a" />

Step 3: VirtualBox opens up automatically and puts in Kali Linux for you 
<img width="975" height="827" alt="image" src="https://github.com/user-attachments/assets/db5fee4d-0a34-4f0e-ab71-5550b220b49b" />

Step 4 : Power on Kali Linux VM Step 5: User = kali pw = kali  
<img width="975" height="863" alt="image" src="https://github.com/user-attachments/assets/529034d9-bc26-4ba6-a1dc-3b0fcd55ca80" />
Step 5: User = kali pw = kali
<img width="975" height="790" alt="image" src="https://github.com/user-attachments/assets/efd93596-ef11-41d5-b34f-f71227749c1e" />
<img width="975" height="829" alt="image" src="https://github.com/user-attachments/assets/6a7fb6ae-9dfc-4384-85a2-00f78c949b81" />

#### Creating Snapshots to revert to baseline config
Step 1: Click on intended VM > Snapshots > on top right, click take  
<img width="975" height="769" alt="image" src="https://github.com/user-attachments/assets/fb303237-18a0-4b45-a5a0-8d46b77c18c7" />

Step 2: Name the snapshot to your preference    
<img width="742" height="579" alt="image" src="https://github.com/user-attachments/assets/ab3b562e-57ad-4a95-b46f-339cbe683dee" />
<img width="975" height="765" alt="image" src="https://github.com/user-attachments/assets/cf1347ff-35d4-4492-9e8b-9f11bf9e28a4" />

### Configuring VMs Based On Use Case Scenario
Step 1: Before we start configuring our VMs we must know what each network settings on VirtualBox do so we know which one to use based on any lab scenario you might test.  
 
NAT: Default mode; VM accesses the internet through the host (safe, isolated).
<img width="975" height="704" alt="image" src="https://github.com/user-attachments/assets/d656bf36-a140-43a3-a253-c4cb8289749b" />

Bridged Adapter: VM appears as a device on the same network as the host.  
<img width="975" height="679" alt="image" src="https://github.com/user-attachments/assets/219c2e35-5fad-4692-b942-e01a8f0b0cd3" />

Internal Network: VMs can communicate only with each other (no host or internet access).  
<img width="975" height="733" alt="image" src="https://github.com/user-attachments/assets/e5990364-2895-4cfd-8cbc-beb0760f2462" />

Host-only Adapter: VM communicates only with the host machine and other host-only VMs.  
<img width="975" height="723" alt="image" src="https://github.com/user-attachments/assets/f2c583a7-0a83-4eeb-91cc-5eea32681c6c" />

Generic Driver: Advanced/custom networking via external drivers.

NAT Network: Similar to NAT but allows multiple VMs on the same internal NATed subnet.  
<img width="975" height="735" alt="image" src="https://github.com/user-attachments/assets/a3a5b17e-cf06-4767-a326-7e17bc66ac71" />

Cloud Network (Experimental): Connects VM to cloud-based virtual networks (testing feature).
Not Attached: No network connection; VM sees no network hardware.  
<img width="975" height="752" alt="image" src="https://github.com/user-attachments/assets/5800bf95-03b2-4c7d-9a25-6e0634ff2ee7" />

#### Scenario 1: Testing Tools That Require Internet Connectivity
Step 1: This is simple. Use NAT and default settings for you Win11 Pro and Kali Linux VM in VirtualBox.    
<img width="975" height="765" alt="image" src="https://github.com/user-attachments/assets/ebded70a-6a7c-44c5-a365-131e71ba8ccd" />
<img width="975" height="642" alt="image" src="https://github.com/user-attachments/assets/233c0990-cd5c-405f-8f98-1ad5cddb9fd5" />
<img width="975" height="652" alt="image" src="https://github.com/user-attachments/assets/4ae0faa7-1525-416d-ab34-b330af96d008" />
Step 2: Repeat the same step into Kali Linux VM to “NAT”. It should be NAT already by default.

#### Scenario 2: Analyzing Malware Recommended Settings









  







 



 



















  
