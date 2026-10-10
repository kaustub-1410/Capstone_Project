import os
import subprocess
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

class RealWorldMitigationRunner:
    """Generates and executes firewall containment policies and Ansible playbooks."""

    PLAYBOOKS_DIR = os.path.join(os.path.dirname(__file__), "..", "playbooks")

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        os.makedirs(self.PLAYBOOKS_DIR, exist_ok=True)

    def execute_quarantine_rules(self, os_type: str = "windows") -> Dict[str, Any]:
        """
        Applies local system firewall block rules to quarantine/isolate the current system.
        Warning: In non-dry_run mode, this will disrupt network connectivity.
        """
        os_type = os_type.lower()
        commands = []
        
        if "win" in os_type:
            # Windows Defender Firewall rules to block all traffic
            commands = [
                'netsh advfirewall firewall add rule name="AMCDS_QUARANTINE_IN" dir=in action=block description="AMCDS Quarantine Containment"',
                'netsh advfirewall firewall add rule name="AMCDS_QUARANTINE_OUT" dir=out action=block description="AMCDS Quarantine Containment"'
            ]
        else:
            # Linux iptables rules to drop incoming/outgoing packets
            commands = [
                'iptables -A INPUT -j DROP',
                'iptables -A OUTPUT -j DROP'
            ]

        result = {
            "commands": commands,
            "dry_run": self.dry_run,
            "status": "skipped (dry_run)"
        }

        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute containment commands:\n" + "\n".join(commands))
            # Save commands to script file for reference
            script_ext = "bat" if "win" in os_type else "sh"
            script_path = os.path.join(self.PLAYBOOKS_DIR, f"containment_script.{script_ext}")
            try:
                with open(script_path, "w") as f:
                    if "win" not in os_type:
                        f.write("#!/bin/bash\n")
                    f.write("\n".join(commands) + "\n")
                result["script_path"] = os.path.abspath(script_path)
            except Exception as e:
                logger.error(f"Failed to write script: {e}")
        else:
            logger.warning(f"EXECUTING HOST CONTAINMENT FIREWALL RULES!")
            success = True
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except Exception as e:
                    logger.error(f"Failed to execute command '{cmd}': {e}")
                    success = False
            result["status"] = "success" if success else "failed"

        return result

    def execute_port_block(self, port: int, os_type: str = "windows") -> Dict[str, Any]:
        """Blocks incoming network connections on a specific port."""
        os_type = os_type.lower()
        commands = []
        
        if "win" in os_type:
            commands = [
                f'netsh advfirewall firewall add rule name="AMCDS_BLOCK_PORT_{port}" dir=in action=block protocol=TCP localport={port} description="AMCDS Port Block"'
            ]
        else:
            commands = [
                f'iptables -A INPUT -p tcp --dport {port} -j DROP'
            ]

        result = {
            "commands": commands,
            "dry_run": self.dry_run,
            "status": "skipped (dry_run)"
        }

        if self.dry_run:
            logger.info(f"[DRY RUN] Would execute port block commands:\n" + "\n".join(commands))
        else:
            success = True
            for cmd in commands:
                try:
                    subprocess.run(cmd, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                except Exception as e:
                    logger.error(f"Failed to execute command '{cmd}': {e}")
                    success = False
            result["status"] = "success" if success else "failed"

        return result

    def generate_ansible_playbook(self, action_name: str, target_host: str, target_ip: str, port: int = None) -> str:
        """Generates a standard Ansible playbook for automated remote containment."""
        playbook_content = ""
        
        if action_name == "isolate_host":
            playbook_content = f"""---
- name: Incident Response - Host Quarantine
  hosts: {target_host}
  become: yes
  vars:
    target_ip: "{target_ip}"
  tasks:
    - name: Block all traffic via iptables (Linux)
      ansible.builtin.iptables:
        chain: INPUT
        jump: DROP
        comment: AMCDS Quarantine containment
      when: ansible_facts['os_family'] != 'Windows'

    - name: Block all traffic via Windows Firewall (Windows)
      community.windows.win_firewall_rule:
        name: AMCDS Quarantine Block
        direction: in
        action: block
        enable: yes
        state: present
      when: ansible_facts['os_family'] == 'Windows'
"""
        elif action_name == "block_port" and port is not None:
            playbook_content = f"""---
- name: Incident Response - Block Port {port}
  hosts: {target_host}
  become: yes
  tasks:
    - name: Block port {port} via iptables (Linux)
      ansible.builtin.iptables:
        chain: INPUT
        protocol: tcp
        destination_port: {port}
        jump: DROP
        comment: AMCDS incident response
      when: ansible_facts['os_family'] != 'Windows'

    - name: Block port {port} via Windows Firewall (Windows)
      community.windows.win_firewall_rule:
        name: AMCDS Block Port {port}
        localport: {port}
        protocol: tcp
        direction: in
        action: block
        enable: yes
        state: present
      when: ansible_facts['os_family'] == 'Windows'
"""
        else:
            playbook_content = f"""---
- name: Security Remediation - General Actions
  hosts: {target_host}
  become: yes
  tasks:
    - name: Audit open network connections
      ansible.builtin.command: netstat -pant
      register: connections
    - name: Print open connections
      ansible.builtin.debug:
        var: connections.stdout_lines
"""

        # Write playbook to a file
        playbook_path = os.path.join(self.PLAYBOOKS_DIR, f"contain__{target_host}__{action_name}.yml")
        try:
            with open(playbook_path, "w") as f:
                f.write(playbook_content)
            logger.info(f"Ansible playbook exported to {os.path.abspath(playbook_path)}")
        except Exception as e:
            logger.error(f"Failed to export Ansible playbook: {e}")

        return playbook_content
