Absolutely! Here’s your **updated and complete installation/configuration guide** based on everything you’ve done, but this time with **OpenVAS running on Kali Linux** (not Worker VM 2 Ubuntu), **integration with ELK**, and **organized for clarity**.
You can **copy-paste directly**. Every required file, folder, and config is here.

---

# **AI-Driven Security Solution – Complete Setup (Kali + Ubuntu Workers + ELK Integration)**

---

## **1. Base Installation (All VMs)**

Run these commands on **ALL three VMs** (Server, Worker 1, Kali):

```bash
# Update system
sudo apt update
sudo apt upgrade -y

# Install system dependencies
sudo apt install -y python3 python3-pip python3-dev build-essential libssl-dev libffi-dev python3-setuptools python3-venv git curl wget gnupg2

# Install additional tools
sudo apt install -y nmap tcpdump wireshark tshark net-tools libzmq3-dev

# Set up Python virtual environment
python3 -m venv ~/security-venv
echo 'source ~/security-venv/bin/activate' >> ~/.bashrc
source ~/security-venv/bin/activate

# Install base Python packages
pip install --upgrade pip
pip install paramiko requests python-dateutil pytz psutil
```

---

## **2. OpenVAS/GVM Installation (On Kali Linux Only)**

> **Kali Linux replaces Ubuntu Worker 2 for scanning and compliance**

```bash
# On KALI LINUX VM ONLY

# Update system
sudo apt update && sudo apt upgrade -y

# Install OpenVAS (GVM)
sudo apt install -y gvm

# Setup OpenVAS (this may take a while)
sudo gvm-setup

# Start OpenVAS services
sudo gvm-start

# (Optional) Reset admin password if you forgot:
# sudo gvmd --user=admin --new-password=YourStrongPasswordHere

# Access Web UI: https://192.168.43.146:9392
```

**You will perform vulnerability scanning and export reports from Kali. See section 6 for forwarding results to ELK.**

---

## **3. Worker VM 2 Setup (192.168.43.21, Ubuntu) – Compliance, Monitoring**

**Do not run OpenVAS here. Only compliance and monitoring (Lynis, Metricbeat, Packetbeat) run on Ubuntu Worker 2.**

### **3.1 Create Project Structure**

```bash
# Create project directory
mkdir -p ~/security-solution-worker
cd ~/security-solution-worker

# Create project subdirectories
mkdir -p config data logs scripts
```

### **3.2 Install Required Libraries**

```bash
source ~/security-venv/bin/activate

# Install worker libraries
pip install pandas numpy requests python-nmap pyzmq grpcio grpcio-tools protobuf

# Install additional security tools
sudo apt install -y nmap lynis

# Install Elasticsearch client for Python (match your ELK stack version)
pip install elasticsearch==8.9.0
```

---

### **3.3 Create Worker Configuration**

```bash
sudo nano ~/security-solution-worker/config/worker_config.json
```

Paste and adjust as needed:

```json
{
  "server": {
    "host": "192.168.43.144",
    "port": 5555
  },
  "worker_id": "worker2",
  "worker_type": "compliance",
  "elk": {
    "elasticsearch": {
      "hosts": ["http://192.168.43.144:9200"],
      "compliance_index": "compliance_results",
      "vuln_index": "vulnerabilities"
    }
  },
  "compliance": {
    "interval": 86400,
    "frameworks": {
      "CIS": [
        {
          "name": "Check SSH root login",
          "command": "grep PermitRootLogin /etc/ssh/sshd_config"
        },
        {
          "name": "Check password auth",
          "command": "grep PasswordAuthentication /etc/ssh/sshd_config"
        }
      ]
    }
  }
}
```

---

### **3.4 Worker Python Scripts**

**Upload or copy your scripts (as you already have):**

* `compliance_checker.py`
* `message_queue.py`

If you want my sample code for these, just ask! Otherwise, you already have the working ones.

**To copy `message_queue.py` from server:**

```bash
scp ubuntu@192.168.43.144:~/security-solution/scripts/message_queue.py ~/security-solution-worker/scripts/
```

---

### **3.5 Set Up Worker Services**

```bash
# Vulnerability scanner not needed here, so just compliance checker!

# Create systemd service for the compliance checker
sudo tee /etc/systemd/system/security-solution-compliance-checker.service > /dev/null << 'EOF'
[Unit]
Description=AI-Driven Security Solution Compliance Checker
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/home/ubuntu/security-solution-worker
ExecStart=/home/ubuntu/security-venv/bin/python /home/ubuntu/security-solution-worker/scripts/compliance_checker.py --config config/worker_config.json
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable security-solution-compliance-checker.service
```

---

### **3.6 Configure Beats Agents**

#### **Metricbeat**

```bash
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.9.2-amd64.deb
sudo dpkg -i metricbeat-8.9.2-amd64.deb
```

**Edit config:**

```bash
sudo nano /etc/metricbeat/metricbeat.yml
```

Edit the output:

```yaml
output.logstash:
  hosts: ["192.168.43.144:5044"]
```

**Enable and start:**

```bash
sudo systemctl enable metricbeat
sudo systemctl start metricbeat
sudo systemctl status metricbeat
```

#### **Packetbeat**

```bash
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-8.9.2-amd64.deb
sudo dpkg -i packetbeat-8.9.2-amd64.deb
```

**Edit config:**

```bash
sudo nano /etc/packetbeat/packetbeat.yml
```

Edit the output:

```yaml
output.logstash:
  hosts: ["192.168.43.144:5044"]
```

**Enable and start:**

```bash
sudo systemctl enable packetbeat
sudo systemctl start packetbeat
sudo systemctl status packetbeat
```

---

## **4. Worker VM 1 (192.168.43.187, Ubuntu) – Log Collection, Monitoring**

(Similar steps as above, adapt worker\_config.json and roles as needed)

---

## **5. Server VM (192.168.43.144) – ELK, Message Queue, SIEM**

You already have ELK stack running.
Message queue server is running as before:

```bash
cd ~/security-solution/scripts
python message_queue.py --host 0.0.0.0 --port 5555 --server
```

---

## **6. OpenVAS/Kali Linux → Forward Results to ELK**

### **A. Export Scan Results from Web UI**

1. Go to https\://\192.168.43.146:9392 and log in.
2. Run a scan, then **Export the report as XML, JSON, or CSV**.

### **B. Forwarding to ELK**

**Option 1: Use Logstash to Import**

* On your server, create a Logstash pipeline to ingest OpenVAS scan results.

**Example for CSV:**

```bash
# Place the CSV file from OpenVAS on the server
# (for example, /home/ubuntu/openvas_report.csv)

sudo nano /etc/logstash/conf.d/openvas.conf
```

Paste:

```conf
input {
  file {
    path => "/home/ubuntu/openvas_report.csv"
    start_position => "beginning"
    sincedb_path => "/dev/null"
  }
}

filter {
  csv {
    separator => ","
    skip_header => "true"
    columns => ["name","host","port","threat","description"]
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "openvas_results"
  }
  stdout { codec => rubydebug }
}
```

Restart Logstash:

```bash
sudo systemctl restart logstash
```

**Check in Kibana:**
Go to the `openvas_results` index.

---

**Option 2: Use Python Script to Forward to Elasticsearch**

* If you want a script to upload results (CSV/JSON/XML), just ask!

---

## **7. Starting and Testing the System**

* **Start your server and message queue.**
* **Start and enable compliance services on workers.**
* **Start OpenVAS on Kali, scan, and export results to ELK.**
* **Start Metricbeat and Packetbeat on all workers.**
* **Monitor all results in Kibana!**

---

## **Directory Structure Example (on Ubuntu Worker/Kali)**

```
~/security-solution-worker/
├── config/
│   └── worker_config.json
├── data/
├── logs/
├── scripts/
│   ├── compliance_checker.py
│   └── message_queue.py
```

---

**If you need any specific script (for forwarding, automation, or full example files), let me know!**
You are now set for a true hybrid Ubuntu-Kali-ELK security lab with OpenVAS, Lynis, Nmap, Metricbeat, Packetbeat, and SIEM dashboards.
Let me know if you want more “ready-to-run” Python or Logstash configs!
