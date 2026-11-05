
#RPM AMD64

sudo systemctl mask wazuh-agent
curl -o wazuh-agent-4.14.3-1.x86_64.rpm https://packages.wazuh.com/4.x/yum/wazuh-agent-4.14.3-1.x86_64.rpm && sudo WAZUH_MANAGER='127.0.0.1' WAZUH_AGENT_GROUP='default' WAZUH_AGENT_NAME='Splunk' rpm -ihv wazuh-agent-4.14.3-1.x86_64.rpm && \
sudo cp ossec.conf /var/ossec/etc/ossec.conf && \
sudo chown root:wazuh /var/ossec/etc/ossec.conf && \
sudo chmod 640 /var/ossec/etc/ossec.conf && \
sudo systemctl unmask wazuh-agent && \
sudo systemctl restart wazuh-agent && \
sudo systemctl enable wazuh-agent
