# Malware Detection Using Wazuh and VirusTotal

<img width="1916" height="899" alt="404428279-adf58f88-f339-4dde-a02b-2d7ab98d5599" src="https://github.com/user-attachments/assets/80643000-a687-4e5c-bd91-466a4eeb8d8d" />




## Objective
This lab demonstrates real-time malware detection by integrating Wazuh SIEM with 
VirusTotal's threat intelligence platform. A Windows 10 endpoint is monitored using 
Wazuh's File Integrity Monitoring (FIM) module, which triggers automated VirusTotal 
hash lookups when suspicious files are created or modified. This simulates a 
core SOC capability — detecting malicious files on endpoints before they can 
execute and cause damage.

---

## MITRE ATT&CK Coverage

| Technique | ID | Description |
|---|---|---|
| Defense Evasion | T1027 | Obfuscated Files or Information |
| Execution | T1204 | User Execution: Malicious File |
| Discovery | T1083 | File and Directory Discovery |
| Command & Control | T1071 | Application Layer Protocol |

---

## Tools & Technologies

- **Wazuh** — Open source SIEM and XDR platform
- **VirusTotal** — Multi-engine threat intelligence and file scanning
- **VirtualBox** — Hypervisor for lab environment
- **Windows 10 VM** — Monitored endpoint (Wazuh agent)
- **Wazuh OVA** — Manager/server running on Linux
- **PowerShell** — Agent deployment and service management
- **ossec.conf** — Wazuh configuration file edited for FIM and VirusTotal integration

---

## Lab Environment
```
┌─────────────────────┐         ┌──────────────────────┐
│   Wazuh Manager     │◄───────►│   Windows 10 Agent   │
│   (Linux OVA)       │         │   (Monitored Host)   │
│   Wazuh Dashboard   │         │   FIM: /Documents    │
└────────┬────────────┘         └──────────────────────┘
         │
         ▼
┌─────────────────────┐
│   VirusTotal API    │
│   (Hash Lookup)     │
└─────────────────────┘
```

---

## Setup & Configuration

### Step 1 — Deploy Wazuh Manager

Install Wazuh using the official OVA file in VirtualBox. After booting, retrieve 
the IP address via `ifconfig` and access the Wazuh dashboard at 
`https://<WAZUH_IP_ADDRESS>`.

<img width="1149" height="975" alt="404427654-3ddcca8c-76bc-4f90-a325-484e94667070" src="https://github.com/user-attachments/assets/00bf2786-8d26-4c45-a357-ba2115ed7706" />


<img width="1488" height="812" alt="404428053-26781699-dd39-4669-bd3f-b5610fc14b0a" src="https://github.com/user-attachments/assets/72646f50-c007-4916-b614-59702e8d3296" />


---

### Step 2 — Deploy Wazuh Agent on Windows 10

Navigate to **Agents → Deploy New Agent** in the Wazuh dashboard. Select Windows 
as the OS, enter the Wazuh server address, and name the agent. Copy the generated 
PowerShell script and run it on the Windows 10 machine to install and register 
the agent.

<img width="1916" height="899" alt="404428279-adf58f88-f339-4dde-a02b-2d7ab98d5599" src="https://github.com/user-attachments/assets/ce23ead5-a72d-4162-8bac-17c92cf43871" />


<img width="1461" height="748" alt="404428466-75682676-793a-4446-b50b-33ac4ee8c6d0" src="https://github.com/user-attachments/assets/93ab60ba-352e-4b19-a8a7-30a06b7933dd" />


<img width="1454" height="711" alt="404428724-e9986edb-c39f-44d2-8f43-d0d8bf204df0" src="https://github.com/user-attachments/assets/aac1c591-faa3-4dfc-aacc-4e918a618704" />


After running the script, start the Wazuh service:

<img width="1213" height="666" alt="404429080-7a2dfc56-ec06-4553-aa38-fc690a13c850" src="https://github.com/user-attachments/assets/4f1a92fa-2067-47cf-b3e0-bc9d3a69481b" />



Confirm the agent appears as active in the Wazuh dashboard:

<img width="1912" height="996" alt="404429315-c2b6782f-3c6e-454f-8a3f-c4850e704a4a" src="https://github.com/user-attachments/assets/d86a334d-12ad-4a89-9f45-0e25b3f9b471" />


---

### Step 3 — Configure VirusTotal Integration

Create a free VirusTotal account at virustotal.com and retrieve your API key 
from your profile settings.

<img width="1905" height="760" alt="404435864-06fd759a-019f-4628-b282-7d1792ee26a6" src="https://github.com/user-attachments/assets/b5dc45ee-4c9c-4b8b-8778-083a6abae336" />

<img width="1917" height="274" alt="404436192-369282d8-258e-496f-8d2f-ea7c697da07a" src="https://github.com/user-attachments/assets/88885c5e-9d1c-4262-935f-e7dda8ac57dc" />


On the Wazuh Manager, edit `/var/ossec/etc/ossec.conf` and add the VirusTotal 
integration block inside the `<ossec_config>` tag, then restart the Wazuh Manager:

<img width="574" height="410" alt="404553474-105c151d-b9a0-4a8d-9392-1d5891b6ce61" src="https://github.com/user-attachments/assets/c929a02c-8554-4e68-b069-60ce0391f053" />


<img width="570" height="73" alt="404553534-251dbf3c-a6ca-4bfe-8a6d-8f56edf4f27a" src="https://github.com/user-attachments/assets/fe9f5a13-0ec0-4b1a-938a-39dbd1ccf862" />


---

### Step 4 — Configure File Integrity Monitoring (FIM)

On the Windows agent, edit the ossec.conf file at 
`C:\\Program Files (x86)\\ossec-agent\\ossec.conf`. Set `<disabled>` to `no` 
to enable FIM, then add the Documents folder as a monitored directory in 
near real-time:

<img width="569" height="67" alt="404553620-69433fe0-9069-4b20-ae91-d4d1ce3397a8" src="https://github.com/user-attachments/assets/691da135-bb85-454e-93f3-15acb364d3f8" />


<img width="1195" height="522" alt="404553632-28c2f6cb-7eed-4528-9c86-3cc513422cdf" src="https://github.com/user-attachments/assets/acb6dc15-42fd-4b5f-8328-05bdc5f9df69" />


Restart the Wazuh agent on Windows to apply the changes:

<img width="337" height="292" alt="404553657-fd2ea94b-fb42-4c71-baaa-840acf6deeb9" src="https://github.com/user-attachments/assets/986b0c8a-c138-441c-b24a-2da682f965a6" />


---

## Detection Use Case — EICAR Malware Test

To validate the detection chain, download the EICAR anti-malware test file 
from eicar.org and drop it into the monitored Documents folder.

> **Note:** Disable Chrome's Enhanced Security and Windows Defender Real-Time 
> Protection temporarily to allow the test file to be written to disk.

### Detection Results

Two alerts fire in sequence on the Wazuh dashboard:

**Alert 1 — FIM detects new file creation:**

<img width="1488" height="838" alt="404553717-2b7d4670-b9cb-4f1e-a092-cacd735ca731" src="https://github.com/user-attachments/assets/b914ee1d-53d2-4c5d-829a-dc82465714a9" />


The FIM module immediately flags that a new file has been added to the 
monitored directory, triggering the VirusTotal integration.

**Alert 2 — VirusTotal confirms malicious file:**

<img width="1488" height="820" alt="404553751-43c960f0-41ad-41d9-8c18-2cd894f099f3" src="https://github.com/user-attachments/assets/c3770979-10f4-4014-8e1e-3a94ace748ab" />


The VirusTotal integration fires an alert showing multi-engine detection 
of the EICAR test file, confirming the file as malicious and completing 
the automated detection chain.

---

## Key Findings

- Wazuh FIM successfully detected file creation in the monitored directory 
  within seconds of the file being dropped
- The VirusTotal API integration automatically submitted the file hash and 
  returned a positive malware detection without manual analyst intervention
- The complete detection chain from file creation to confirmed alert 
  required no manual triage — demonstrating automated threat detection 
  at the endpoint level
- This integration replicates a real SOC capability: automated IOC 
  enrichment via threat intelligence platforms

---

## SOC Skills Demonstrated

- SIEM deployment and agent management (Wazuh)
- File Integrity Monitoring (FIM) configuration
- Third-party threat intelligence API integration (VirusTotal)
- Linux configuration file editing (ossec.conf)
- Windows endpoint security monitoring
- Alert triage and investigation workflow
- Endpoint Detection and Response (EDR) concepts
