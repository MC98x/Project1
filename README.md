## Cybersecurity Home Lab Setup and Threat Telemetry Analysis

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



















  







 



 



















  
