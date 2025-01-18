# Wazuh-Lab
Malware detection using VirusTotal and Wazuh

## Objective

You will be detecting malware in real time using Wazuh and VirusTotal.  The detection and eradication of malware is essential for 
keeping systems running and stopping unauthorized access, data breaches, and financial losses. VirusTotal will help us scan any suspicious file
against hundreds of Antivirus engines. Using Wazuh will provide a capability to integrate VirusTotal to detect malware in real-time across the network.

What is VirusTotal?
A well-known platform in the field of cybersecurity, VirusTotal is a free service that brings together a number of antivirus engines and web scanners to look over suspicious files and URLs. Its strength is that it uses a lot of different antivirus signatures and heuristic detection methods to look at possible dangers in a thorough way.

**Requirement**

-Virtualbox

-Windows 10 VM

-Wazuh OVA File

**Home-Lab Set up**

Step1: Install Wazuh, using Wazuh OVA file.  You can download this on the official Wazuh website.

![image](https://github.com/user-attachments/assets/1efe990a-41b1-44b8-bad9-dbdee9f986ec)

Open the file in Virtualbox and start the Virtual Machine

![image](https://github.com/user-attachments/assets/3ddcca8c-76bc-4f90-a325-484e94667070)

Now, log in to Wazuh CLI and run ifconfig to get the IP address.

The default Wazuh CLI credential is

username: wazuh-user

password: wazuh

Once, you have the IP address, open your favourite browser and submit the URL https://<WAZUH_IP_ADDRESS>

Next, enter the Wazuh GUI credential as shown below

username: admin

password: admin

![image](https://github.com/user-attachments/assets/26781699-dd39-4669-bd3f-b5610fc14b0a)

Step2: Install Wazuh Agent on Windows 10

If your host OS is Windows, you can go for installing locally or else you can download the Windows 10/11 Virtual Edition from Microsoft's official website

Once your Windows 10 machine is ready, visit the Wazuh platform using GUI. Go to Agents and click on Deploy new agent, as shown below.

![image](https://github.com/user-attachments/assets/adf58f88-f339-4dde-a02b-2d7ab98d5599)

Next, select an Operating system, enter your Wazuh Server address, and set your agent name as shown below.

![image](https://github.com/user-attachments/assets/75682676-793a-4446-b50b-33ac4ee8c6d0)

In the end, you will get a PowerShell script and a command to start the Wazuh service on your agent, as shown below.

![image](https://github.com/user-attachments/assets/e9986edb-c39f-44d2-8f43-d0d8bf204df0)

Next, go to your Windows 10 Machine and the script in your Powershell command prompt.

![image](https://github.com/user-attachments/assets/890f4d5f-6e69-4ae4-8015-5cbb66270dac)

Next, start the Wazuh service.

![image](https://github.com/user-attachments/assets/7a2dfc56-ec06-4553-aa38-fc690a13c850)

Finally, come back to your Wazuh platform and go to Agents; you should see your newly onboarded Windows agent here

![image](https://github.com/user-attachments/assets/c2b6782f-3c6e-454f-8a3f-c4850e704a4a)

Step3: Set up VirusTotal account and retreive API key

Visit virustotal.com and sign up with your email address. Go to profile and click on API key.

![image](https://github.com/user-attachments/assets/06fd759a-019f-4628-b282-7d1792ee26a6)

To copy the API key and click next to API key and save it somewhere.

![image](https://github.com/user-attachments/assets/369282d8-258e-496f-8d2f-ea7c697da07a)

Step4: Integrate Virustotal on Wazuh Manager

Login to your Wazuh Manager and open the ossec.conf file located at /var/ossec/etc/ossec.conf. Next add the below block at the end within the <ossec_config> tag

![image](https://github.com/user-attachments/assets/105c151d-b9a0-4a8d-9392-1d5891b6ce61)

Next, restart the wazuh Manager using below command

![image](https://github.com/user-attachments/assets/251dbf3c-a6ca-4bfe-8a6d-8f56edf4f27a)

Step5: Setting up Wazuh Agent to detect any file changes


Search for the <syscheck> block in the Wazuh agent C:\Program Files (x86)\ossec-agent\ossec.conf file. Make sure that <disabled> is set to no. This enables the Wazuh FIM module to monitor for directory changes.

Add an entry within the <syscheck> block to configure a directory to be monitored in near real-time. In this lab, we will move our malware sample in this Documents folder.

![image](https://github.com/user-attachments/assets/69433fe0-9069-4b20-ae91-d4d1ce3397a8)

![image](https://github.com/user-attachments/assets/28c2f6cb-7eed-4528-9c86-3cc513422cdf)

Now, lets restart the wazuh agent on Windows.

![image](https://github.com/user-attachments/assets/fd2ea94b-fb42-4c71-baaa-840acf6deeb9)

**Use Case**

In this use case, we will test suspicious files using Virustotal. For this use case, we will use eicar test file. You can download it from their official website https://www.eicar.org/download-anti-malware-testfile/

Note: You need to disable the Enhanced security option on Google Chrome and Real-time Security on Windows Defender.

Next, move the file into Document folder.

Once done, you should see the alerts on Wazuh Manager as shown below.


First alert says a new file has been added.

![image](https://github.com/user-attachments/assets/2b7d4670-b9cb-4f1e-a092-cacd735ca731)

Second alert shows the Virustotal engine detection.

![image](https://github.com/user-attachments/assets/43c960f0-41ad-41d9-8c18-2cd894f099f3)

This shows that Virustotal and Wazuh combined together can be used for live malware detection. We have also learned the integration of Virustotal with Wazuh platform is extremly seamless.

