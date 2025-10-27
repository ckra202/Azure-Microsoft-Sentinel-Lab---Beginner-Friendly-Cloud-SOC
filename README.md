# Azure + Microsoft Sentinel Lab --- Detect Multiple Failed SSH Logins

**Objective:**  
Simulate and detect brute-force SSH login attempts using Microsoft Sentinel, Azure Monitor Agent, and Syslog on a Linux VM.  
This lab demonstrates how Azure-native security tools collect, analyze, and respond to authentication anomalies in a cloud environment.

---

## 🧩 Lab Overview

| Component | Description |
|------------|-------------|
| **VM Name** | `vm-buntu-target` (Ubuntu 22.04 LTS) |
| **Region** | East US 2 |
| **Monitoring Agent** | Azure Monitor Agent (AMA) |
| **Data Sources** | Syslog (`auth`, `authpriv`, `daemon`) |
| **SIEM** | Microsoft Sentinel |
| **Workspace** | `law-aisec-eastus2` |
| **Rule Name** | `Multiple Failed SSH Logins` |
| **Detection Threshold** | ≥ 5 failed attempts in 30 minutes |
| **Incident Severity** | Medium |

---

## ⚙️ Azure Resource Deployment (Portal)

You can deploy all components through the **Azure Portal** manually — or use PowerShell alternatives (see below).

### **1️⃣ Create Resource Group and Log Analytics Workspace**

Portal path:  
- Go to **Resource Groups → + Create → Name: RG-AIsec-Lab → Region: East US 2**  
- Then go to **Log Analytics Workspaces → + Create → Name: law-aisec-eastus2 → Link to RG-AIsec-Lab**

💡 **PowerShell alternative:**
```powershell
# Variables
$rgName = "RG-AIsec-Lab"
$location = "eastus2"
$workspaceName = "law-aisec-eastus2"

# Create resource group
New-AzResourceGroup -Name $rgName -Location $location

# Create Log Analytics workspace
New-AzOperationalInsightsWorkspace -ResourceGroupName $rgName -Name $workspaceName -Location $location -Sku "PerGB2018"
```

<img width="789" height="377" alt="Screenshot 2025-10-27 093850" src="https://github.com/user-attachments/assets/41854be2-8289-4db6-84e8-9bf748c9eddc" />

<img width="747" height="353" alt="image" src="https://github.com/user-attachments/assets/7a57df79-bf3f-4c3b-9595-3e564031162e" />


### **2️⃣ Create Ubuntu VM and Connect AMA**

Portal path:

Go to Virtual Machines → + Create → Ubuntu 22.04 LTS → Standard D2als v6 (2 vcpus, 4 GiB memory) → SSH key pair login

Allow port 22 inbound, assign a public IP.

After creation, go to Extensions + Applications → Add → Azure Monitor Agent (AMA) → Link to law-aisec-eastus2.

💡 **PowerShell alternative:**
```Markdown
$vmName = "vm-buntu-target"
$vmSize = "Standard D2als v6 (2 vcpus, 4 GiB memory)"
$cred = Get-Credential -Message "Enter VM credentials"

```
 New-AzVM -ResourceGroupName $rgName -Name $vmName -Location $location `
  -Image "Canonical:0001-com-ubuntu-server-jammy:22_04-lts-gen2:latest" `
  -PublicIpAddressName "$vmName-ip" -OpenPorts 22 -Size $vmSize -Credential $cred
# Attach Azure Monitor Agent
Set-AzVMExtension -ResourceGroupName $rgName -VMName $vmName `
  -Name "AzureMonitorLinuxAgent" -Publisher "Microsoft.Azure.Monitor" `
  -ExtensionType "AzureMonitorLinuxAgent" -TypeHandlerVersion "1.10" -Location $location
```
```

<img width="861" height="404" alt="image" src="https://github.com/user-attachments/assets/eaa7881b-116f-45ca-8b8a-82a1e1b66dfb" />

<img width="506" height="700" alt="image" src="https://github.com/user-attachments/assets/4ec57e39-8577-4ef2-94f9-fd4cd914df11" />


### **3️⃣ Enable Microsoft Sentinel**

Portal path:

Go to Microsoft Sentinel → + Create → Select existing workspace → law-aisec-eastus2 → Add

💡 PowerShell alternative: 

` Set-AzSentinelOnboardingState -ResourceGroupName $rgName -WorkspaceName $workspaceName -Enable $true `

<img width="770" height="298" alt="image" src="https://github.com/user-attachments/assets/f64e56f8-f657-48eb-96d8-83302562c96e" />

## 🧱 Sentinel Configuration
### **4️⃣ Create Data Collection Rule (DCR)

Portal path:

Monitor → Data Collection Rules → +Create
Add Syslog facilities: auth, authpriv, daemon
Severity: info

Link the DCR to vm-buntu-target.

💡 **PowerShell alternative:**
```
New-AzDataCollectionRule `
  -Name "dcr-aisec" `
  -ResourceGroupName $rgName `
  -Location $location `
  -DataFlowDestination $workspaceName `
  -SyslogFacility @("auth","authpriv","daemon") `
  -SyslogSeverity @("info")
```


<img width="856" height="309" alt="image" src="https://github.com/user-attachments/assets/c95f61d6-4af4-4d3d-9bd0-c56c01009ca9" />

<img width="719" height="403" alt="image" src="https://github.com/user-attachments/assets/543b560d-70fe-4d8c-91bf-b09624df2ad2" />

### **5️⃣ Enable Password Authentication on VM**

Portal path:
SSH into VM → Edit /etc/ssh/sshd_config.d/50-cloud-init.conf →

```markdown
PasswordAuthentication yes
ChallengeResponseAuthentication no
```
Save and restart SSH service.

<img width="586" height="87" alt="image" src="https://github.com/user-attachments/assets/4243373b-69e6-47fa-8b24-4987d6fd4f5c" />


💡 **PowerShell alternative:**

```
Invoke-AzVMRunCommand -ResourceGroupName $rgName -VMName $vmName `
  -CommandId "RunShellScript" `
  -ScriptString 'sudo sed -i "s/^PasswordAuthentication.*/PasswordAuthentication yes/" /etc/ssh/sshd_config.d/50-cloud-init.conf && sudo systemctl restart sshd'
```

<img width="536" height="29" alt="image" src="https://github.com/user-attachments/assets/893df23f-064b-4d48-862a-a9eed5f559cb" />

### 6️⃣ Generate Failed SSH Logins

From your local terminal:
```
ssh -o PubkeyAuthentication=no azureuser@<VM_PUBLIC_IP>
```

Enter the wrong password 5–10 times.

<img width="686" height="482" alt="image" src="https://github.com/user-attachments/assets/fcd4c60e-ed76-49e6-b7d7-eba1ac0e479f" />

### **7️⃣ Verify Syslog Data**

Portal path:
Microsoft Sentinel → Logs → Run the query below:

```kql
Syslog
| where TimeGenerated > ago(10m)
| where SyslogMessage has "Failed password"
| project TimeGenerated, Facility, Computer, SyslogMessage
| sort by TimeGenerated desc
```

### **8️⃣ Create Analytics Rule**

Portal path:
Sentinel → Configuration → Analytics → + Create → Scheduled Query Rule → Paste the query below:
```kql
let threshold = 5;
Syslog
| where Facility in ("auth","authpriv")
| where SyslogMessage has_any ("Failed password","Invalid user")
| extend SrcIP = extract(@'from ([0-9\.]+) port',1,SyslogMessage)
| summarize FailedCount = count(),
           FirstSeen=min(TimeGenerated),
           LastSeen  = max(TimeGenerated)
           by SrcIP, HostName
| where FailedCount >= threshold
```

<img width="1489" height="368" alt="image" src="https://github.com/user-attachments/assets/b74d0b1d-9820-4f2e-8b60-1c3ac4b0bbea" />

### **9️⃣ Validate Incident Creation**

Go to Microsoft Sentinel → Threat management → Incidents

Wait for next rule run (≈5 min)

Verify incident: “Multiple Failed SSH Logins”
<img width="855" height="566" alt="image" src="https://github.com/user-attachments/assets/4a14f439-6223-46c8-98f4-d40ad329e4b0" />


##🧠 **Reflection & Learning Outcomes**

- Understood Azure Monitor Agent and DCR-based Syslog ingestion

- Practiced secure SSH configuration management

- Built an end-to-end detection pipeline (logs → KQL → alert → incident)

- Strengthened incident response and triage workflow in Sentinel

- Learned how to mix Portal configuration and PowerShell automation


**🔒 After testing, revert to secure SSH settings:**
```
PasswordAuthentication no
sudo systemctl restart sshd
```
