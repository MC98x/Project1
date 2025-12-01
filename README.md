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

#### I. Advanced Detection and Automation 

* **Custom Correlation Rules:** Develop specific, high-fidelity alerts within Splunk that trigger when a sequence of suspicious events occurs (e.g., a process execution followed immediately by a network connection to an unknown external IP).
    * *Goal:* Reduce alert fatigue by creating rules based on confirmed **Tactics, Techniques, and Procedures (TTPs)** rather than single events.
* **Dashboard Development:** Build a dedicated **Threat Triage Dashboard** in Splunk to visualize key Sysmon data (Process, Network, File activity) and facilitate rapid, efficient incident review.
* **MITRE ATT&CK Mapping:** Map all simulated attacker actions (e.g., Execution, Command and Control) to the appropriate **MITRE ATT&CK Framework** techniques to build a structured defense plan.

#### II. Network and External Telemetry 

* **Introduce Network Security Monitoring (NSM):** Integrate a dedicated open-source NSM tool like **Security Onion** or **Suricata/Zeek** on a separate VM.
* **Layered Logging:** Begin ingesting network flow logs and Intrusion Detection System (IDS) alerts alongside the host-based Sysmon data. This will allow for true **defense-in-depth** analysis by cross-validating endpoint telemetry with network traffic.

#### III. Expanded Threat Simulation & Complexity 

* **Simulate Persistence:** Conduct new simulations targeting persistence mechanisms, such as modifying the Windows Registry (**Run Keys**) or creating scheduled tasks. Analyze the resulting **Sysmon Registry EventCodes (12, 13, 14)** to build targeted registry monitoring rules.
* **Credential Theft Simulation:** Utilize tools like Mimikatz (safely within the isolated lab) to simulate credential dumping and focus on detecting the suspicious process access events that precede successful theft.

---

### Conclusion

This project successfully achieved its core objective: deploying a fully isolated, instrumented home lab capable of high-fidelity threat detection and analysis. The work confirmed proficiency across several critical domains relevant to a Security Operations Center (SOC) role:

* **Detection Engineering Proficiency:** Successfully deployed and integrated industry-standard host logging (**Sysmon**) with a leading **SIEM** platform (**Splunk**), demonstrating the ability to establish and maintain an effective security monitoring infrastructure.
* **Log Triage & Incident Analysis:** Used **Splunk Search Processing Language (SPL)** to efficiently triage logs, specifically isolating and analyzing the attack chain's most critical event (**Process Creation, EventCode 1**).
* **Critical Thinking & Anomaly Detection:** The analysis went beyond simple alert confirmation. It identified the **anomalous behavior** of the malicious `resume.pdf.exe` spawning the legitimate **`WerFault.exe`** (Windows Error Reporting). This demonstrated the ability to detect subtle **Indicators of Compromise (IOCs)** and understand common attacker techniques (e.g., using a crash to obscure execution), a core competency for SOC Analysts.
* **Systems and Network Hardening:** Established a secure, segmented lab environment (192.168.20.0/24), showcasing practical systems administration and network isolation skills crucial for safe, repeatable threat testing.

