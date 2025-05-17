<<<<<<< HEAD
# ELK Stack Installation Guide for Ubuntu 22.04.5

This guide provides step-by-step instructions for installing and configuring the Elastic Stack (ELK) on Ubuntu 22.04.5, along with Beats agents (Auditbeat, Filebeat, Metricbeat, and Packetbeat) for comprehensive log shipping and system monitoring. The installation follows the Directory Structure Overview and Architecture Overview from the original documentation.

## Prerequisites

- Ubuntu 22.04.5 installed on the Server VM and Worker VMs
- Minimum system requirements for each VM:
  - CPU: 2 cores
  - RAM: 4 GB
  - Disk Space: 100 GB 
=======
# ELK Installation Guide for Kali Linux 2024.4

This guide provides step-by-step instructions for installing and configuring the Elastic Stack (ELK) on Kali Linux 2024.4, along with Beats agents (Auditbeat, Filebeat, Metricbeat, and Packetbeat) for log shipping and monitoring. The installation will be based on the provided Directory Structure Overview and Architecture Overview.

## Prerequisites

- Kali Linux 2024.4 installed on the Server VM and Worker VMs
- Sufficient system resources (CPU, RAM, and disk space) for running the Elastic Stack and Beats agents
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
- Network connectivity between the Server VM and Worker VMs

## Installation Steps

### 1. Server VM

#### 1.1 Install Java

```bash
sudo apt update
sudo apt install default-jdk -y
```

#### 1.2 Install Elasticsearch

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
sudo apt-get install apt-transport-https
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/8.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-8.x.list
sudo apt-get update && sudo apt-get install elasticsearch
```
<<<<<<< HEAD
--------------------------- Security autoconfiguration information ------------------------------

Authentication and authorization are enabled.
TLS for the transport and HTTP layers is enabled and configured.

The generated password for the elastic built-in superuser is : 1JCIyLmytJ_4LhTEQh8u

If this node should join an existing cluster, you can reconfigure this with
'/usr/share/elasticsearch/bin/elasticsearch-reconfigure-node --enrollment-token <token-here>'
after creating an enrollment token on your existing cluster.

You can complete the following actions at any time:

Reset the password of the elastic built-in superuser with 
'/usr/share/elasticsearch/bin/elasticsearch-reset-password -u elastic'.

Generate an enrollment token for Kibana instances with 
 '/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana'.

Generate an enrollment token for Elasticsearch nodes with 
'/usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s node'.

-------------------------------------------------------------------------------------------------

=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

#### 1.3 Configure Elasticsearch

```bash
sudo nano /etc/elasticsearch/elasticsearch.yml
```

Uncomment and modify the following lines:

```yaml
network.host: 0.0.0.0
xpack.security.enabled: false
```

Enable and start the Elasticsearch service:

```bash
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch
sudo systemctl status elasticsearch
<<<<<<< HEAD
=======

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

#### 1.4 Install Logstash

```bash
sudo apt install logstash
```

#### 1.5 Configure Logstash

```bash
sudo nano /etc/logstash/conf.d/beats.conf
```

Add the following content:

```ruby
input {
  beats {
    port => 5044
  }
}

filter {
  if [type] == "syslog" {
    grok {
      match => { "message" => "%{SYSLOGLINE}" }
    }
    date {
      match => [ "timestamp", "MMM  d HH:mm:ss", "MMM dd HH:mm:ss" ]
    }
  }

  if [type] == "apache" {
    grok {
      match => { "message" => "%{COMBINEDAPACHELOG}" }
    }
    date {
      match => [ "timestamp", "dd/MMM/yyyy:HH:mm:ss Z" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["localhost:9200"]
    index => "%{[@metadata][beat]}-%{+YYYY.MM.dd}"
  }
}
```

Enable and start the Logstash service:

```bash
sudo systemctl enable logstash
sudo systemctl start logstash
sudo systemctl status logstash
<<<<<<< HEAD
=======

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

#### 1.6 Install Kibana

```bash
sudo apt install kibana
```

#### 1.7 Configure Kibana

```bash
sudo nano /etc/kibana/kibana.yml
```

Uncomment and modify the following lines:

```yaml
server.port: 5601
<<<<<<< HEAD
server.host: "0.0.0.0" 
elasticsearch.hosts: ["192.168.18.215:9200"]
=======
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

Enable and start the Kibana service:

```bash
sudo systemctl enable kibana
<<<<<<< HEAD
sudo systemctl start kibana  
sudo systemctl status kibana
=======
sudo systemctl start kibana
sudo systemctl status kibana

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

### 2. Worker VM 1

#### 2.1 Install Filebeat

```bash
<<<<<<< HEAD
sudo apt update
sudo apt install curl -y
=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.9.2-amd64.deb
sudo dpkg -i filebeat-8.9.2-amd64.deb
```

#### 2.2 Configure Filebeat

```bash
<<<<<<< HEAD
sudo nano /etc/filebeat/filebeat.yml  
```

=======
sudo nano /etc/filebeat/filebeat.yml
```
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
Modify the following lines:

```yaml
filebeat.inputs:
- type: filestream
<<<<<<< HEAD
  id: system-logs
  enabled: true
  paths:
    - /var/log/*.log
  tags: ["system"]
  fields:
    source_type: syslog
    environment: security

- type: filestream
  id: security-solution-logs
  enabled: true
  paths:
    - /home/ubuntu/security-solution-worker/logs/*.log
  tags: ["security-solution"]
  fields:
    source_type: application
    environment: security

output.logstash:
  hosts: ["192.168.100.66:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.

Enable and start the Filebeat service:  
=======
  id: syslog-filestream
  enabled: true
  paths:
    - /var/log/*.log
    - /var/log/apache2/*.log
  tags: ["syslog"]

output.logstash:
  hosts: ["192.168.100.55:5044"]
```

Replace `192.168.100.55` with the IP address of the Server VM.

Enable and start the Filebeat service:
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

```bash
sudo systemctl enable filebeat
sudo systemctl start filebeat
sudo systemctl status filebeat
<<<<<<< HEAD
=======

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

#### 2.3 Install Auditbeat

<<<<<<< HEAD
```bash 
sudo apt update
sudo apt install curl -y
=======
```bash
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
curl -L -O https://artifacts.elastic.co/downloads/beats/auditbeat/auditbeat-8.9.2-amd64.deb
sudo dpkg -i auditbeat-8.9.2-amd64.deb
```

#### 2.4 Configure Auditbeat

```bash
sudo nano /etc/auditbeat/auditbeat.yml
```

Modify the output section:

```yaml
output.logstash:
<<<<<<< HEAD
  hosts: ["10.12.56.152:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.
=======
  hosts: ["192.168.100.55:5044"]
```

Replace `192.168.100.55` with the IP address of the Server VM.
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

Enable and start the Auditbeat service:

```bash
<<<<<<< HEAD
sudo systemctl enable auditbeat  
sudo systemctl start auditbeat
sudo systemctl status auditbeat  
=======
sudo systemctl enable auditbeat
sudo systemctl start auditbeat
sudo systemctl status auditbeat

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

### 3. Worker VM 2

#### 3.1 Install Metricbeat

```bash
<<<<<<< HEAD
sudo apt update
sudo apt install curl -y
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.9.2-amd64.deb
sudo dpkg -i metricbeat-8.9.2-amd64.deb  
=======
curl -L -O https://artifacts.elastic.co/downloads/beats/metricbeat/metricbeat-8.9.2-amd64.deb
sudo dpkg -i metricbeat-8.9.2-amd64.deb
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

#### 3.2 Configure Metricbeat

<<<<<<< HEAD
```bash 
=======
```bash
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
sudo nano /etc/metricbeat/metricbeat.yml
```

Modify the output section:

```yaml
output.logstash:
<<<<<<< HEAD
  hosts: ["10.12.56.152:5044"] 
```

Replace `10.12.56.152` with the IP address of the Server VM.
=======
  hosts: ["192.168.100.55:5044"]
```

Replace `192.168.100.55` with the IP address of the Server VM.
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

Enable and start the Metricbeat service:

```bash
sudo systemctl enable metricbeat
<<<<<<< HEAD
sudo systemctl start metricbeat 
sudo systemctl status metricbeat
=======
sudo systemctl start metricbeat
sudo systemctl status metricbeat

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

#### 3.3 Install Packetbeat

```bash
<<<<<<< HEAD
sudo apt update
sudo apt install curl -y
=======
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
curl -L -O https://artifacts.elastic.co/downloads/beats/packetbeat/packetbeat-8.9.2-amd64.deb
sudo dpkg -i packetbeat-8.9.2-amd64.deb
```

<<<<<<< HEAD
#### 3.4 Configure Packetbeat  

```bash
sudo nano /etc/packetbeat/packetbeat.yml  
=======
#### 3.4 Configure Packetbeat

```bash
sudo nano /etc/packetbeat/packetbeat.yml
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

Modify the output section:

<<<<<<< HEAD
```yaml 
output.logstash:
  hosts: ["10.12.56.152:5044"]
```

Replace `10.12.56.152` with the IP address of the Server VM.
=======
```yaml
output.logstash:
  hosts: ["192.168.100.55:5044"]
```

Replace `192.168.100.55` with the IP address of the Server VM.
>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15

Enable and start the Packetbeat service:

```bash
sudo systemctl enable packetbeat
sudo systemctl start packetbeat
<<<<<<< HEAD
sudo systemctl status packetbeat  
=======
sudo systemctl status packetbeat

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
```

## Verification

<<<<<<< HEAD
1. Access Kibana by navigating to `http://192.168.18217:5601` in a web browser.

2. Click on "Discover" in the left-hand panel to view the incoming logs and data from the Beats agents.

3. Explore the pre-built dashboards and visualizations for each Beat in the "Dashboard" section. 

4. Customize the dashboards and create new visualizations based on your specific requirements.





yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
=======
1. Access Kibana by navigating to `http://192.168.100.55:5601` `http:192.168.18.209
:5601` in a web browser.

2. Click on "Discover" in the left-hand panel to view the incoming logs and data from the Beats agents.

3. Explore the pre-built dashboards and visualizations for each Beat in the "Dashboard" section.

4. Customize the dashboards and create new visualizations based on your specific requirements.

>>>>>>> 6f437e4c0711f5641cf446fd3904f7607f3a8d15
