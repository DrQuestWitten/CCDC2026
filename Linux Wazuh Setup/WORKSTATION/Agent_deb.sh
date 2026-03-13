#!/bin/bash

#sudo systemctl mask wazuh-agent
wget https://packages.wazuh.com/4.x/apt/pool/main/w/wazuh-agent/wazuh-agent_4.14.3-1_amd64.deb && sudo WAZUH_MANAGER='172.20.242.20' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Ub-WKS' dpkg -i ./wazuh-agent_4.14.3-1_amd64.deb && \
sudo cp ossec.conf /var/ossec/etc/ossec.conf && \
sudo chown root:wazuh /var/ossec/etc/ossec.conf && \
sudo chmod 640 /var/ossec/etc/ossec.conf && \
sudo systemctl unmask wazuh-agent && \
sudo systemctl restart wazuh-agent && \
sudo systemctl enable wazuh-agent
