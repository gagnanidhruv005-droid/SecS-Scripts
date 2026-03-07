#!/bin/bash

echo "==============================="
echo "   Wazuh Agent Auto Installer  "
echo "==============================="

# Ask Manager IP
read -p "Enter Wazuh Manager IP: " MANAGER_IP

echo ""
echo "Updating system..."
sudo apt update -y

echo "Installing dependencies..."
sudo apt install curl apt-transport-https unzip wget gnupg -y

echo "Adding Wazuh GPG key..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
sudo gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "Adding Wazuh repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
sudo tee /etc/apt/sources.list.d/wazuh.list

echo "Updating repository..."
sudo apt update -y

echo "Installing Wazuh agent..."
sudo apt install wazuh-agent -y

echo "Configuring manager IP..."

sudo sed -i "s/<address>MANAGER_IP<\/address>/<address>$MANAGER_IP<\/address>/g" /var/ossec/etc/ossec.conf
sudo sed -i "s/<address>127.0.0.1<\/address>/<address>$MANAGER_IP<\/address>/g" /var/ossec/etc/ossec.conf

echo "Registering agent with manager..."
sudo /var/ossec/bin/agent-auth -m $MANAGER_IP

echo "Starting Wazuh agent..."
sudo systemctl daemon-reexec
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent

echo ""
echo "==============================="
echo " Wazuh Agent Installed!"
echo " Manager: $MANAGER_IP"
echo "==============================="

sudo systemctl status wazuh-agent