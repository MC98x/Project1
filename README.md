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

#### Installing VirtualBox
Step 1: Head to https://www.virtualbox.org/wiki/Downloads and click download. 
<img width="975" height="731" alt="image" src="https://github.com/user-attachments/assets/f3fe5736-ef0e-4657-b1c4-4172bd811086" />

Step 1.2: Choose the operating system you are using… in my case Windows. 
<img width="975" height="675" alt="image" src="https://github.com/user-attachments/assets/88bc5a72-cc3b-45d8-a20b-d7fe249548a5" />

Step 2.1: Compare Hash values to verify integrity of installer. 
<img width="975" height="906" alt="image" src="https://github.com/user-attachments/assets/fb1546b5-882c-44fc-b69b-1ce014e524f9" />

Step 2.2 Find the VirtualBox version of what you downloaded inside the checksum list. In my case “VirtualBox-7.2.4-170995-Win.exe” 
<img width="975" height="423" alt="image" src="https://github.com/user-attachments/assets/a5fe0d1e-2723-4774-831d-5ff766179b67" />

Step 2.3 Go to where you downloaded the file > Right Click > Then click “Open in Terminal” 
<img width="975" height="467" alt="image" src="https://github.com/user-attachments/assets/87b9cc9f-b69a-436d-9fc9-12c2d8cf1a8b" />

**Step2.4:** This will open up powershell and in powershell type command 



  







 



 



















  
