# NETWORK SECURITY INTEGRATION

### Overview
The Network Security Integration project combines multiple industry-leading security tools to provide a comprehensive and scalable solution for protecting networks against various cyber threats. By integrating Snort, Suricata, Wazuh, and Splunk, this project ensures robust intrusion detection, threat analysis, and efficient log management. It centralizes log collection and leverages Azure's cloud infrastructure to deliver a scalable, efficient, and easy-to-deploy security solution for organizations of all sizes.

### Features
- **Snort**: Real-time traffic analysis and packet logging.
- **Suricata**: Advanced network intrusion detection and prevention.
- **Wazuh**: Threat detection, integrity monitoring, and incident response.
- **Splunk**: Advanced log analysis and visualization.
- **Centralized Log Collection**: Streamlined management of logs and events across nodes.
- **Scalable Infrastructure**: Deployment leveraging Azure for reliability and scalability.
- **Customizable Rules and Policies**: Tailored detection and prevention mechanisms.

### Requirements
- **Software Dependencies**:
  - Wazuh (latest version)
  - Splunk Enterprise
  - Snort or Suricata
- **Hardware Requirements**:
  - Minimum 8GB RAM and 4 CPU cores for the central server.
  - Adequate disk space for logs and analysis (recommended: 100GB+).
- **Cloud Services**:
  - Azure subscription for Wazuh deployment.

### Getting Started

### Running Snort
1. Start Snort:
   ```bash
   snort -i eth0 -c /etc/snort/snort.conf
   ```
2. Test Network Traffic:
   Simulate traffic to validate detection rules.

### Configuration
- **Wazuh**:
  - Modify `wazuh.conf` for agent and server settings.
  - Deploy agents on monitored nodes.
- **Splunk**:
  - Configure Splunk forwarders to receive Wazuh logs.
  - Set up dashboards for visualization.
- **Suricata and Snort**:
  - Update configuration files for traffic monitoring rules.

### Custom Rules
- **Snort Rules**:
  ```bash
  alert tcp any any -> any 80 (msg:"HTTP Access Detected"; sid:1000001; rev:1;)
  ```
- **Suricata Rules**:
  ```bash
  alert icmp any any -> any any (msg:"ICMP Traffic Detected"; sid:1000002; rev:1;)
  ```

