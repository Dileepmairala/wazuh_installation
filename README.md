
# Wazuh Installation Guide

This guide provides step-by-step instructions for installing Wazuh 4.9 on a single-node or multi-node configuration.

## Prerequisites

- CentOS/RHEL operating system
- Root privileges
- Network connectivity between nodes
- Required ports open

## Installation Steps

### 1. Generate Certificates

```bash
# Download the wazuh-certs-tool.sh script and the config.yml
curl -sO https://packages.wazuh.com/4.9/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.9/config.yml
```

Edit `config.yml` to define your node structure:

```yaml
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "172.16.1.175"
    #- name: node-2
    #  ip: "<indexer-node-ip>"
    #- name: node-3
    #  ip: "<indexer-node-ip>"
  # Wazuh server nodes
  # If there is more than one Wazuh server
  # node, each one must have a node_type
  server:
    - name: wazuh-1
      ip: "172.16.1.176"
    #  node_type: master
    #- name: wazuh-2
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
    #- name: wazuh-3
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "172.16.1.176"
```

Generate certificates:

```bash
bash ./wazuh-certs-tool.sh -A
```

Example output:
```
INFO:
26/09/2024 11:03:53 INFO: Generating the root certificate.
26/09/2024 11:03:53 INFO: Generating Admin certificates.
26/09/2024 11:03:54 INFO: Admin certificates created.
26/09/2024 11:03:54 INFO: Generating Wazuh indexer certificates.
26/09/2024 11:03:54 INFO: Wazuh indexer certificates created.
26/09/2024 11:03:54 INFO: Generating Filebeat certificates.
26/09/2024 11:03:54 INFO: Wazuh Filebeat certificates created.
26/09/2024 11:03:54 INFO: Generating Wazuh dashboard certificates.
26/09/2024 11:03:54 INFO: Wazuh dashboard certificates created.
```

Compress the certificates:

```bash
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates
```

### 2. Install Wazuh Indexer

Install required packages:

```bash
yum install coreutils

# Import the GPG key and add the Wazuh repository
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

# Install the Wazuh indexer
yum -y install wazuh-indexer
```

> Note: For multi-node configuration, edit `/etc/wazuh-indexer/opensearch.yml` and uncomment the node section. For single node, no changes are required.

Configure the certificates:

```bash
NODE_NAME=node-1
mkdir /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

Start the Wazuh indexer service:

```bash
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer

# Initialize security settings
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

Test the installation:

```bash
curl -k -u admin:admin https://[WAZUH_INDEXER_IP_ADDRESS]:9200
```

Expected output:
```json
{
  "name" : "node-1",
  "cluster_name" : "wazuh-cluster",
  "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
  "version" : {
    "number" : "7.10.2",
    "build_type" : "rpm",
    "build_hash" : "db90a415ff2fd428b4f7b3f800a51dc229287cb4",
    "build_date" : "2023-06-03T06:24:25.112415503Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

### 3. Install Wazuh Server

Import GPG key and add repository:

```bash
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
```

Install Wazuh manager and Filebeat:

```bash
# Install Wazuh manager
yum -y install wazuh-manager

# Install Filebeat
yum -y install filebeat

# Download Filebeat configuration
curl -so /etc/filebeat/filebeat.yml https://packages.wazuh.com/4.9/tpl/wazuh/filebeat/filebeat.yml
```

Edit the `/etc/filebeat/filebeat.yml` file and replace `hosts: ["127.0.0.1:9200"]` with your Wazuh indexer address.

Configure Filebeat keystore:

```bash
# Create keystore
filebeat keystore create

# Add credentials
echo admin | filebeat keystore add username --stdin --force
echo admin | filebeat keystore add password --stdin --force

# Download the alerts template
curl -so /etc/filebeat/wazuh-template.json https://raw.githubusercontent.com/wazuh/wazuh/v4.9.0/extensions/elasticsearch/7.x/wazuh-template.json
chmod go+r /etc/filebeat/wazuh-template.json

# Install Wazuh module for Filebeat
curl -s https://packages.wazuh.com/4.x/filebeat/wazuh-filebeat-0.4.tar.gz | tar -xvz -C /usr/share/filebeat/module
```

Setup certificates for Filebeat:

```bash
NODE_NAME=wazuh-1
mkdir /etc/filebeat/certs
tar -xf ./wazuh-certificates.tar -C /etc/filebeat/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/filebeat/certs/$NODE_NAME.pem /etc/filebeat/certs/filebeat.pem
mv -n /etc/filebeat/certs/$NODE_NAME-key.pem /etc/filebeat/certs/filebeat-key.pem
chmod 500 /etc/filebeat/certs
chmod 400 /etc/filebeat/certs/*
chown -R root:root /etc/filebeat/certs
```

Edit `/var/ossec/etc/ossec.conf` to configure the indexer connection. Replace `0.0.0.0` with your Wazuh indexer node IP address.

Start the services:

```bash
# Start Wazuh manager
systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

# Start Filebeat
systemctl daemon-reload
systemctl enable filebeat
systemctl start filebeat
```

Verify Filebeat installation:

```bash
filebeat test output
```

Expected output:
```
elasticsearch: https://172.16.1.176:9200...
  parse url... OK
  connection...
    parse host... OK
    dns lookup... OK
    addresses: 172.16.1.176
    dial up... OK
  TLS...
    security: server's certificate chain verification is enabled
    handshake... OK
    TLS version: TLSv1.3
    dial up... OK
  talk to server... OK
  version: 7.10.2
```

### 4. Install Wazuh Dashboard

Install required packages:

```bash
yum install libcap

# Import the GPG key
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH

# Add the repository
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo

# Install Wazuh dashboard
yum -y install wazuh-dashboard
```

Edit the `/etc/wazuh-dashboard/opensearch_dashboards.yml` file and replace `opensearch.hosts: https://localhost:9200` with your Wazuh indexer IP address.

Configure certificates:

```bash
NODE_NAME=dashboard
mkdir /etc/wazuh-dashboard/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-dashboard/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./root-ca.pem
mv -n /etc/wazuh-dashboard/certs/$NODE_NAME.pem /etc/wazuh-dashboard/certs/dashboard.pem
mv -n /etc/wazuh-dashboard/certs/$NODE_NAME-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
chmod 500 /etc/wazuh-dashboard/certs
chmod 400 /etc/wazuh-dashboard/certs/*
chown -R wazuh-dashboard:wazuh-dashboard /etc/wazuh-dashboard/certs
```

Start the dashboard service:

```bash
systemctl daemon-reload
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard
```

Edit the `/usr/share/wazuh-dashboard/data/wazuh/config/wazuh.yml` file and replace the URL with your Wazuh server IP address:

```yaml
hosts:
   - default:
      url: https://[WAZUH_SERVER_IP_ADDRESS]
      port: 55000
      username: wazuh-wui
      password: wazuh-wui
      run_as: false
```

### 5. Access the Wazuh Dashboard

Access the Wazuh web interface with your credentials:
- URL: `https://[WAZUH_DASHBOARD_IP_ADDRESS]`
- Username: `admin`
- Password: `admin`

## Troubleshooting

### Common Issues

1. **Certificate Issues**: Ensure certificates are properly configured and permissions are set correctly
2. **Connection Problems**: Verify that firewall rules allow traffic on required ports
3. **Service Failures**: Check service logs with `journalctl -u <service-name>`

### Logs Location

- Wazuh manager: `/var/ossec/logs/ossec.log`
- Wazuh indexer: `/var/log/wazuh-indexer/wazuh-cluster.log`
- Wazuh dashboard: `/var/log/wazuh-dashboard/opensearch-dashboards.log`
- Filebeat: `/var/log/filebeat/filebeat`

## Security Recommendations

1. Change default passwords immediately after installation
2. Configure firewall rules to restrict access to Wazuh components
3. Regularly update Wazuh to the latest version
4. Implement secure communication (HTTPS) for external access

## Additional Resources

- [Wazuh Documentation](https://documentation.wazuh.com/)
- [Wazuh GitHub Repository](https://github.com/wazuh/wazuh)
- [Wazuh Support Forum](https://groups.google.com/forum/#!forum/wazuh)
