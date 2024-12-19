#!/usr/bin/env bash

# Full cleanup before installation
if systemctl is-active --quiet wazuh-agent; then
    echo "Stopping Wazuh agent..."
    sudo systemctl stop wazuh-agent
fi

if dpkg -l | grep -q wazuh-agent; then
    echo "Removing Wazuh agent..."
    sudo apt purge -y wazuh-agent
fi

if [ -f /usr/share/keyrings/wazuh-archive-keyring.gpg ]; then
    echo "Removing Wazuh GPG key..."
    sudo rm -f /usr/share/keyrings/wazuh-archive-keyring.gpg
fi

if [ -f /etc/apt/sources.list.d/wazuh.list ]; then
    echo "Removing Wazuh repository..."
    sudo rm -f /etc/apt/sources.list.d/wazuh.list
fi

sudo apt update && sudo apt autoremove -y && sudo apt clean

# Check if Ansible is installed
if ! command -v ansible &> /dev/null
then
    echo "Ansible not found. Installing Ansible..."
    sudo apt update && sudo apt install -y ansible || { echo "Failed to install Ansible"; exit 1; }
fi

# Ensure the directory exists
if [ ! -d "/home/ansible-scripts" ]; then
    sudo mkdir -p /home/ansible-scripts
    # Optional: change ownership if needed
    sudo chown root:root /home/ansible-scripts
fi

# Create the Ansible playbook file
sudo tee /home/ansible-scripts/install-wazuh.yml > /dev/null <<'EOF'
---
- name: Install and configure Wazuh agent on local machine
  hosts: localhost
  become: yes
  gather_facts: yes
  connection: local

  vars:
    wazuh_manager_ip: "192.168.100.18"  # Replace with your Wazuh manager IP/hostname
    registration_password: "<REGISTRATION_PASSWORD>"    # Replace with your actual registration password

  tasks:
    - name: Ensure necessary packages are installed (Debian/Ubuntu)
      apt:
        name:
          - curl
          - gnupg
          - apt-transport-https
          - lsb-release
        state: present
        update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Add Wazuh GPG key (Debian/Ubuntu)
      ansible.builtin.shell:
        cmd: "curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh-archive-keyring.gpg"
      when: ansible_os_family == "Debian"

    - name: Add Wazuh repository (Debian/Ubuntu)
      apt_repository:
        repo: "deb [signed-by=/usr/share/keyrings/wazuh-archive-keyring.gpg] https://packages.wazuh.com/4.x/apt stable main"
        state: present
      when: ansible_os_family == "Debian"

    - name: Update package cache (Debian/Ubuntu)
      apt:
        update_cache: yes
      when: ansible_os_family == "Debian"

    - name: Install Wazuh agent
      package:
        name: "wazuh-agent"
        state: present

    - name: Configure Wazuh agent - manager address
      lineinfile:
        path: /var/ossec/etc/ossec.conf
        regexp: '<address>.*</address>'
        line: "<address>{{ wazuh_manager_ip }}</address>"
        insertafter: '<auth>'

    - name: Remove duplicate agent (if exists)
      shell: "/var/ossec/bin/agent_control -r -n $(hostname)"
      ignore_errors: yes
      when: ansible_os_family == "Debian"

    - name: Register this agent with the Wazuh manager
      command: "wazuh-agent-auth -m {{ wazuh_manager_ip }} -p {{ registration_password }} -A $(hostname)"
      register: wazuh_registration
      changed_when: "'Agent key imported' in wazuh_registration.stdout or 'already registered' in wazuh_registration.stdout"
      failed_when: "'ERROR' in wazuh_registration.stderr"

    - name: Start Wazuh agent and enable it at boot
      systemd:
        name: wazuh-agent
        enabled: yes
        state: started
EOF

echo "Playbook created at /home/ansible-scripts/install-wazuh.yml."

# Run the Ansible playbook
ansible-playbook /home/ansible-scripts/install-wazuh.yml
if [ $? -eq 0 ]; then
    echo "Wazuh agent installed and enabled at startup"
else
    echo "Playbook failed"
    exit 1
fi
