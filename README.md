# week-2-cybersecurity-intern-tasks
**Description:**  This repository contains the completed tasks for Week 2 of the Cybersecurity Internship, focusing on network monitoring, secure authentication, vulnerability scanning, cryptography, and threat analysis. Each task includes detailed configurations, code implementations, and testing results.
```markdown

## Description

This repository contains the completed tasks for Week 2 of the Cybersecurity Internship, focusing on network monitoring, secure authentication, vulnerability scanning, cryptography, and threat analysis. Each task includes detailed configurations, code implementations, and testing results.

---

## Task 1: Network Monitoring and Intrusion Detection (Snort)

### **1.1 Install Snort**
To begin, Snort was installed on a virtual machine (VM). Use the following commands to install Snort on your VM.

```bash
sudo apt update
sudo apt install snort
```

### **1.2 Snort Configuration**
The Snort configuration file was modified to set up monitoring on a specific network interface and define the rules for detecting malicious activities like SYN floods and ICMP floods.

Edit the `snort.conf` file:

```bash
sudo nano /etc/snort/snort.conf
```

Add the following line to specify the HOME_NET:

```bash
ipvar HOME_NET 192.168.32.0/24
```

To specify the output directory for logs:

```bash
output alert_fast: /var/log/snort/alert
```

### **1.3 Simulated Attacks**
We used `hping3` to simulate traffic patterns such as SYN floods and ICMP floods to test Snort’s ability to detect malicious activity.

```bash
sudo hping3 -S 192.168.32.205 -p 80 --flood
sudo hping3 -1 192.168.32.205
```

### **1.4 View Snort Logs**
After running the simulated attacks, we viewed the Snort logs to verify detection of suspicious activity:

```bash
cat /var/log/snort/alert
```

---

## Task 2: Two-Factor Authentication (2FA) Implementation

### **2.1 Install Open Source 2FA Tool**
We used Google Authenticator along with PAM (Pluggable Authentication Module) to set up two-factor authentication (2FA) on our VM. Install the PAM module:

```bash
sudo apt install libpam-google-authenticator
```

### **2.2 Configure PAM for 2FA**
We edited the PAM configuration file to require Google Authenticator for login.

```bash
sudo nano /etc/pam.d/sshd
```

Add the following line:

```bash
auth required pam_google_authenticator.so
```

### **2.3 Test 2FA**
Once 2FA was configured, we logged out and then attempted to log back in, verifying that the second authentication factor (Google Authenticator) was required.

---

## Task 3: Vulnerability Scanning (Nessus)

### **3.1 Install Nessus**
Nessus was installed on the VM to scan for vulnerabilities.

```bash
sudo apt install -y wget
wget https://www.tenable.com/downloads/api/v1/public/pages/nessus/downloads/12202/download?i_agree_to_tenable_license_agreement=true -O nessus.deb
sudo dpkg -i nessus.deb
```

### **3.2 Run Vulnerability Scan**
Once Nessus was installed, we launched the Nessus web interface on `https://localhost:8834`, created a new scan, and started the vulnerability scan for the VM.

### **3.3 Analyze Results**
After the scan completed, we analyzed the vulnerabilities identified by Nessus, documenting at least three of them along with their potential impact and mitigation strategies.

---

## Task 4: Basic Cryptography (AES Encryption and Decryption)

### **4.1 Install PyCryptodome**
To perform encryption and decryption, we used the `pycryptodome` library. Install it with:

```bash
pip install pycryptodome
```

### **4.2 Python Script for Encryption and Decryption**

#### AES Encryption Example:

```python
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Encryption
key = get_random_bytes(16)  # AES-128
cipher = AES.new(key, AES.MODE_CBC)
data = "Confidential Data".encode()
ciphertext = cipher.encrypt(pad(data, AES.block_size))

# Decryption
decipher = AES.new(key, AES.MODE_CBC, iv=cipher.iv)
decrypted_data = unpad(decipher.decrypt(ciphertext), AES.block_size)
print(f"Decrypted Data: {decrypted_data.decode()}")
```

---

## Task 5: Threat Analysis (Case Study)

### **5.1 Research Cybersecurity Incident**
We analyzed a recent cybersecurity incident, such as a ransomware attack, and examined the nature of the attack, the vulnerabilities exploited, the impact, and the resolution. The case study includes suggestions on measures that could have prevented the attack.

---

## Deliverables

- Snort setup and logs.
- 2FA implementation summary and screenshots.
- Vulnerability scan results and analysis.
- Python script for encryption/decryption.
- Case study write-up.

---
