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

### **Screeshots**

![snort install](https://github.com/user-attachments/assets/7756f4ae-7489-4d5d-bc32-1caf71dfff72)

![config](https://github.com/user-attachments/assets/6a39a5ca-cd76-4e56-82b3-ca5655008c26)

![dns-file](https://github.com/user-attachments/assets/aa2eee12-4e82-4ce0-be4e-a253343d7ae2)

![Screenshot-of-Snort-as-it-is-running](https://github.com/user-attachments/assets/92976731-59e4-4a50-9383-967b4d591e1e)

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

### **Screeshots**

![2fa1 ss](https://github.com/user-attachments/assets/cd67a1b1-f938-4b4c-ac60-902d9c915659)

![2fa2](https://github.com/user-attachments/assets/64851da5-5da8-4964-9be3-7c47d5bd9fc8)

![2fa3](https://github.com/user-attachments/assets/27e1fa8f-aee5-413b-83ae-8b2199003ec2)

![2faPam1](https://github.com/user-attachments/assets/95d77eef-7405-4552-842c-d5e8efe1893e)

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

### **Screeshots**

![ness1](https://github.com/user-attachments/assets/03fbda1f-4bfc-44f3-b0ec-12882e052487)

![ness2](https://github.com/user-attachments/assets/ebb572cc-eb50-4c3f-ae32-8677aaa0df29)

![Screenshot_2024-11-29_20_42_52](https://github.com/user-attachments/assets/02a87329-cef9-4bb7-81e0-583ba4ddf8e1)

![vuln1](https://github.com/user-attachments/assets/9fd03243-a2c5-4ad6-9d05-ee5ee7eee871)

![vuln01](https://github.com/user-attachments/assets/4a4e8aa6-7c38-4b34-a8a4-5829de3bd730)

![vuln2](https://github.com/user-attachments/assets/6012dfa9-68a5-4ac6-a987-017b6508640c)

![vuln3](https://github.com/user-attachments/assets/adf153a2-752c-45ec-8448-41145a335636)


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
