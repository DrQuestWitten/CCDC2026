#!/bin/bash

# --- CCDC Wazuh Windows Agent Registration ---
# Run this on the Manager host AFTER the docker stack is up.
set -ex
echo "## Locating Wazuh Manager container..."

# Dynamically find the container name based on the image name
CONTAINER_NAME=$(docker ps --format '{{.Names}}' | grep "wazuh.manager" | head -n 1)

if [ -z "$CONTAINER_NAME" ]; then
    echo "[!] Error: Could not find a running container with the image 'wazuh/wazuh-manager'."
    echo "    Make sure your docker-compose stack is up and running."
    exit 1
fi

echo "   -> Found Manager: $CONTAINER_NAME"
echo "-------------------------------------------------------"

OUTPUT_FILE="windows_agent_keys.txt"
VMS=("DNS" "IIS" "FTP" "WKS_WIN11")

echo "## Starting Agent Registration..."

# Clear the output file if it already exists
> "$OUTPUT_FILE"

for VM in "${VMS[@]}"; do
    echo "[*] Processing $VM..."
    
    # 1. Register the VM (Corrected flags: -a is IP, -n is Name)
    # Piped 'echo y' to automatically bypass the confirmation prompt
    docker exec -i "$CONTAINER_NAME" bash -c "echo y | /var/ossec/bin/manage_agents -a any -n $VM" > /dev/null 2>&1
    
    # 2. Grab the newly created ID directly from the client.keys file
    AGENT_ID=$(docker exec -i "$CONTAINER_NAME" grep -w "$VM" /var/ossec/etc/client.keys | awk '{print $1}')
    
    # 3. Extract the Base64 import key
    if [ -n "$AGENT_ID" ]; then
        # Grab the raw key string
        KEY=$(docker exec -i "$CONTAINER_NAME" /var/ossec/bin/manage_agents -e "$AGENT_ID" | tail -n 1)
        
        # 4. Save it cleanly to our file
        echo "$VM ($AGENT_ID): $KEY" >> "$OUTPUT_FILE"
        echo "    -> Success! Key generated."
    else
        echo "    -> [!] Failed to find ID for $VM. (Was it already registered?)"
    fi
done

echo "-------------------------------------------------------"
echo "DONE! Keys exported to: $OUTPUT_FILE"
echo "Contents:"
cat "$OUTPUT_FILE"
echo "-------------------------------------------------------"