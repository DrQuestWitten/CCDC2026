#!/bin/bash

## Run the script before the hardening (we need to create some users)
# --- CCDC Wazuh Auto-Deploy for Oracle Linux (RHEL-based) ---
# Purpose: Fast deployment for CCDC environment

set -ex

echo "## [1/5] Adding Repo"
sudo rpm --import https://download.docker.com/linux/centos/gpg
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo

echo "## [2/5] Installing Docker and Git"
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin git curl

echo "## [3/5] Starting Docker and adjusting SELinux"
sudo systemctl enable --now docker

# Temporarily set SELinux to Permissive to allow Docker volume mounts without :z flags
#sudo setenforce 0 || true
# Persist SELinux change
#sudo sed -i 's/^SELINUX=enforcing/SELINUX=permissive/' /etc/selinux/config

echo "## [4/5] Configuring Kernel Parameters for Wazuh Indexer"
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

echo "## [5/5] Deploying Wazuh via Docker Compose"
if [ ! -d "wazuh-docker" ]; then
    git clone https://github.com/wazuh/wazuh-docker.git -b v4.14.3
fi

cd wazuh-docker/single-node
cp ../../local_rules.xml .
cp ../../client.keys .

echo "## Generating SSL Certificates..."
sudo docker compose -f generate-indexer-certs.yml run --rm generator

echo "## Patching local_rules.xml volume mount..."
# Touch the file FIRST so Docker doesn't mount it as a directory
touch local_rules.xml
sed -i 's|.*- wazuh_etc:/var/ossec/etc.*|&\n      - ./local_rules.xml:/var/ossec/etc/rules/local_rules.xml:ro|' docker-compose.yml

echo "## Adjusting Dashboard Session Timeouts..."
# Corrected the path to match the Wazuh repository structure
DASHBOARD_CONF="config/wazuh_dashboard/opensearch_dashboards.yml" 
sudo sed -i '/opensearch_security.session.ttl:/d' $DASHBOARD_CONF 
sudo sed -i '/opensearch_security.cookie.ttl:/d' $DASHBOARD_CONF 
sudo sed -i '/opensearch_security.session.keepalive:/d' $DASHBOARD_CONF

sudo tee -a $DASHBOARD_CONF > /dev/null <<EOT 
opensearch_security.session.ttl: 172800000 
opensearch_security.cookie.ttl: 172800000 
opensearch_security.session.keepalive: true 
EOT

sudo docker compose run --rm --user root \
  -v $(pwd)/client.keys:/tmp/client.keys \
  --entrypoint "/bin/sh -c 'cp /tmp/client.keys /var/ossec/etc/client.keys && chown root:wazuh /var/ossec/etc/client.keys && chmod 640 /var/ossec/etc/client.keys'" \
  wazuh.manager

echo "## Starting Wazuh Stack..."
sudo docker compose up -d

# --- Final Output ---
IP_ADDR=$(hostname -I | awk '{print $1}')
echo "-------------------------------------------------------"
echo "INSTALLATION SUCCESSFUL"
echo "Wazuh Dashboard: https://$IP_ADDR"
echo "User: admin | Pass: SecretPassword"
echo "-------------------------------------------------------"