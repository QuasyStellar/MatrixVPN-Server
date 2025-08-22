#!/usr/bin/env python3
import os
import subprocess
import argparse
import re
import shutil
from datetime import datetime
import json
import sqlite3
import time
from xtlsapi import XrayClient, utils


class SetupConfig:

    def __init__(self, setup_file_path="/root/antizapret/setup"):
        self.config = {}
        self.load_config(setup_file_path)

    def load_config(self, setup_file_path):
        if not os.path.exists(setup_file_path):
            raise FileNotFoundError(f"Setup file not found: {setup_file_path}")
        with open(setup_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    if "=" in line:
                        key, value = line.split("=", 1)
                        self.config[key.strip()] = value.strip()

    def get(self, key, default=None):
        return self.config.get(key, default)


# Global setup config instance
setup_config = None


def handle_error(lineno, command, message=""):
    print(f"Error at line {lineno}: {command}")
    print(f"Message: {message}")
    # Add system info as in the original script
    try:
        lsb_release = subprocess.run(["lsb_release", "-ds"],
                                     capture_output=True,
                                     text=True,
                                     check=True).stdout.strip()
        uname_r = subprocess.run(["uname", "-r"],
                                 capture_output=True,
                                 text=True,
                                 check=True).stdout.strip()
        current_time = datetime.now().isoformat(timespec="seconds")
        print(f"{lsb_release} {uname_r} {current_time}")
    except subprocess.CalledProcessError as e:
        print(f"Could not get system info: {e}")
    exit(1)


def run_command(command_args,
                description="",
                check=True,
                capture_output=True,
                text=True,
                **kwargs):
    """Helper to run shell commands."""
    print(f"Running: {"
          ".join(command_args)}")
    try:
        result = subprocess.run(
            command_args,
            capture_output=capture_output,
            text=text,
            check=check,
            **kwargs,
        )
        if result.stdout:
            print(f"Stdout:\n{result.stdout}")
        if result.stderr:
            print(f"Stderr:\n{result.stderr}")
        return result
    except subprocess.CalledProcessError as e:
        handle_error(
            e.lineno if hasattr(e, "lineno") else "N/A",
            " ".join(command_args),
            f"Command failed with exit code {e.returncode}:\n{e.stderr}",
        )
    except FileNotFoundError:
        handle_error("N/A", " ".join(command_args),
                     f"Command not found: {command_args[0]}")
    except Exception as e:
        handle_error("N/A", " ".join(command_args),
                     f"An unexpected error occurred: {e}")


def ask_client_name(client_name_var=None):
    """Prompts the user for a client name."""
    client_name = client_name_var
    if not client_name or not re.match(r"^[a-zA-Z0-9_-]{1,32}$", client_name):
        print(
            "\nEnter client name: 1–32 alphanumeric characters (a-z, A-Z, 0-9) with underscore (_) or dash (-)"
        )
        while True:
            client_name = input("Client name: ").strip()
            if re.match(r"^[a-zA-Z0-9_-]{1,32}$", client_name):
                break
            else:
                print("Invalid client name. Please try again.")
    return client_name


def ask_client_cert_expire(client_cert_expire_var=None):
    """Prompts the user for client certificate expiration days."""
    client_cert_expire = client_cert_expire_var
    if not client_cert_expire or not (isinstance(client_cert_expire, int)
                                      and 1 <= client_cert_expire <= 3650):
        print("\nEnter client certificate expiration days (1-3650):")
        while True:
            client_cert_expire_input = input(
                "Certificate expiration days: ").strip()
            if client_cert_expire_input.isdigit(
            ) and 1 <= int(client_cert_expire_input) <= 3650:
                client_cert_expire = int(client_cert_expire_input)
                break
            else:
                print(
                    "Invalid expiration days. Please enter a number between 1 and 3650."
                )
    return client_cert_expire


def set_server_host_file_name(client_name, server_host_override=""):
    """Sets SERVER_HOST and FILE_NAME based on client name and server host override."""
    global SERVER_HOST, FILE_NAME
    if not server_host_override:
        SERVER_HOST = SERVER_IP
    else:
        SERVER_HOST = server_host_override

    FILE_NAME = client_name.replace("antizapret-", "").replace("vpn-", "")
    FILE_NAME = f"{FILE_NAME}-({SERVER_HOST})"
    return SERVER_HOST, FILE_NAME


def set_server_ip():
    """Determines the server's IP address."""
    global SERVER_IP
    result = run_command(["ip", "-4", "addr"], capture_output=True, text=True)
    output_lines = result.stdout.splitlines()
    server_ip = None
    for line in output_lines:
        match = re.search(
            r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+ scope global",
            line)
        if match:
            server_ip = match.group(1)
            break
    if not server_ip:
        handle_error("N/A", "ip -4 addr", "Default IP address not found!")
    SERVER_IP = server_ip
    return SERVER_IP


def render(template_file_path, variables):
    """Renders a template file by replacing placeholders."""
    rendered_content = []
    with open(template_file_path, "r") as f:
        for line in f:
            original_line = line  # Keep original line for comparison
            for match in re.finditer(r"\$\{[a-zA-Z_][a-zA-Z_0-9]*\}", line):
                placeholder = match.group(0)  # e.g., ${SERVER_IP}
                var_name = placeholder[2:-1]  # e.g., SERVER_IP
                if var_name in variables:
                    line = line.replace(placeholder, str(variables[var_name]))
                else:
                    # If variable not found, keep placeholder or replace with empty string
                    # Based on shell script's eval behavior, it would likely be empty if undefined
                    line = line.replace(placeholder, "")

            rendered_content.append(line)

    return "".join(rendered_content)


# --- OpenVPN Functions ---
def init_openvpn():
    """Initializes OpenVPN EasyRSA PKI."""
    print("\nInitializing OpenVPN EasyRSA PKI...")
    os.makedirs("/etc/openvpn/easyrsa3", exist_ok=True)
    os.chdir("/etc/openvpn/easyrsa3")

    # Check if CA and server certs exist
    if not (os.path.exists("./pki/ca.crt")
            and os.path.exists("./pki/issued/antizapret-server.crt")
            and os.path.exists("./pki/private/antizapret-server.key")):
        print("PKI not found or incomplete. Initializing new PKI...")
        shutil.rmtree("./pki", ignore_errors=True)
        shutil.rmtree("/etc/openvpn/server/keys", ignore_errors=True)
        shutil.rmtree("/etc/openvpn/client/keys", ignore_errors=True)

        run_command(["/usr/share/easy-rsa/easyrsa", "init-pki"])
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "--req-cn=AntiZapret CA",
                "build-ca",
                "nopass",
            ],
            env={
                "EASYRSA_CA_EXPIRE": "3650",
                **os.environ
            },
        )
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-server-full",
                "antizapret-server",
                "nopass",
            ],
            env={
                "EASYRSA_CERT_EXPIRE": "3650",
                **os.environ
            },
        )
    else:
        print("OpenVPN PKI already initialized.")

    os.makedirs("/etc/openvpn/server/keys", exist_ok=True)
    os.makedirs("/etc/openvpn/client/keys", exist_ok=True)

    # Copy server keys if not present
    if not (os.path.exists("/etc/openvpn/server/keys/ca.crt") and
            os.path.exists("/etc/openvpn/server/keys/antizapret-server.crt")
            and
            os.path.exists("/etc/openvpn/server/keys/antizapret-server.key")):
        print("Copying server keys...")
        shutil.copy("./pki/ca.crt", "/etc/openvpn/server/keys/ca.crt")
        shutil.copy(
            "./pki/issued/antizapret-server.crt",
            "/etc/openvpn/server/keys/antizapret-server.crt",
        )
        shutil.copy(
            "./pki/private/antizapret-server.key",
            "/etc/openvpn/server/keys/antizapret-server.key",
        )
    else:
        print("Server keys already copied.")

    # Generate CRL if not present
    if not os.path.exists("/etc/openvpn/server/keys/crl.pem"):
        print("Generating CRL...")
        run_command(
            ["/usr/share/easy-rsa/easyrsa", "gen-crl"],
            env={
                "EASYRSA_CRL_DAYS": "3650",
                **os.environ
            },
        )
        os.chmod("./pki/crl.pem", 0o644)
        shutil.copy("./pki/crl.pem", "/etc/openvpn/server/keys/crl.pem")
    else:
        print("CRL already exists.")
    os.chdir("/")  # Change back to root


def add_openvpn(client_name, client_cert_expire_days):
    """Adds an OpenVPN client or renews its certificate."""
    print(f"\nAdding/Renewing OpenVPN client: {client_name}")
    set_server_host_file_name(client_name, setup_config.get("OPENVPN_HOST"))
    os.chdir("/etc/openvpn/easyrsa3")

    client_crt_path = f"./pki/issued/{client_name}.crt"
    client_key_path = f"./pki/private/{client_name}.key"
    client_req_path = f"./pki/reqs/{client_name}.req"
    if (os.path.exists(client_crt_path) and not os.path.exists(client_key_path)) or \
       (os.path.exists(client_key_path) and not os.path.exists(client_crt_path)):
        print(
            "Detected inconsistent client state. Cleaning up old keys/certs..."
        )
        for f in [client_crt_path, client_key_path, client_req_path]:
            if os.path.exists(f):
                os.remove(f)

    if not (os.path.exists(client_crt_path)
            and os.path.exists(client_key_path)):
        print("Client does not exist. Building new client certificate.")
        client_cert_expire_days = ask_client_cert_expire(
            client_cert_expire_days)
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-client-full",
                client_name,
                "nopass",
            ],
            env={
                "EASYRSA_CERT_EXPIRE": str(client_cert_expire_days),
                **os.environ
            },
        )
    else:
        print("Client with that name already exists!")
        print("Current client certificate expiration period:")
        for f in [client_crt_path, client_key_path, client_req_path]:
            if os.path.exists(f):
                os.remove(f)
        client_cert_expire_days = ask_client_cert_expire(
            client_cert_expire_days)
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-client-full",
                client_name,
                "nopass",
            ],
            env={
                "EASYRSA_CERT_EXPIRE": str(client_cert_expire_days),
                **os.environ
            },
        )
    # Copy client keys
    if not (os.path.exists(f"/etc/openvpn/client/keys/{client_name}.crt")
            and os.path.exists(f"/etc/openvpn/client/keys/{client_name}.key")):
        print("Copying client keys...")
        shutil.copy(client_crt_path,
                    f"/etc/openvpn/client/keys/{client_name}.crt")
        shutil.copy(client_key_path,
                    f"/etc/openvpn/client/keys/{client_name}.key")
    else:
        print("Client keys already copied.")

    # Get cert contents
    ca_cert_content = run_command([
        "awk",
        "/-----BEGIN CERTIFICATE-----/{flag=1}/-----END CERTIFICATE-----/{print;flag=0;next}flag",
        "/etc/openvpn/server/keys/ca.crt",
    ]).stdout
    client_cert_content = run_command([
        "awk",
        "/-----BEGIN CERTIFICATE-----/{flag=1}/-----END CERTIFICATE-----/{print;flag=0;next}flag",
        f"/etc/openvpn/client/keys/{client_name}.crt",
    ]).stdout
    client_key_content = run_command(
        ["cat", "--", f"/etc/openvpn/client/keys/{client_name}.key"]).stdout

    if not (ca_cert_content and client_cert_content and client_key_content):
        handle_error("N/A", "Key loading", "Cannot load client keys!")

    client_dir = f"/root/antizapret/client/{client_name}"
    os.makedirs(client_dir, exist_ok=True)
    current_date = datetime.now().strftime("%y-%m-%d")

    # Prepare variables for rendering
    render_vars = {
        "SERVER_HOST": SERVER_HOST,
        "CA_CERT": ca_cert_content,
        "CLIENT_CERT": client_cert_content,
        "CLIENT_KEY": client_key_content,
        "SERVER_IP": SERVER_IP,  # Ensure SERVER_IP is available for templates
        **setup_config.config,  # Include all setup config variables
    }

    # Render OpenVPN client config files
    templates = {
        "antizapret-udp.conf": f"AZ-UDP-{current_date}.ovpn",
        "antizapret-tcp.conf": f"AZ-TCP-{current_date}.ovpn",
        "antizapret.conf": f"AZ-U+T-{current_date}.ovpn",
        "vpn-udp.conf": f"GL-UDP-{current_date}.ovpn",
        "vpn-tcp.conf": f"GL-TCP-{current_date}.ovpn",
        "vpn.conf": f"GL-U+T-{current_date}.ovpn",
    }

    for template, output_filename in templates.items():
        template_path = f"/etc/openvpn/client/templates/{template}"
        output_path = os.path.join(client_dir, output_filename)
        rendered_content = render(template_path, render_vars)
        with open(output_path, "w") as f:
            f.write(rendered_content)

    print(
        f"OpenVPN profile files (re)created for client '{client_name}' at {client_dir}"
    )
    os.chdir("/")  # Change back to root


def delete_openvpn(client_name):
    """Deletes an OpenVPN client."""
    print(f"\nDeleting OpenVPN client: {client_name}")
    set_server_host_file_name(client_name, setup_config.get("OPENVPN_HOST"))
    os.chdir("/etc/openvpn/easyrsa3")

    run_command(
        ["/usr/share/easy-rsa/easyrsa", "--batch", "revoke", client_name])
    run_command(
        ["/usr/share/easy-rsa/easyrsa", "gen-crl"],
        env={
            "EASYRSA_CRL_DAYS": "3650",
            **os.environ
        },
    )
    os.chmod("./pki/crl.pem", 0o644)
    shutil.copy("./pki/crl.pem", "/etc/openvpn/server/keys/crl.pem")

    client_dir = f"/root/antizapret/client/{client_name}"
    if os.path.exists(client_dir):
        shutil.rmtree(client_dir)
    if os.path.exists(f"/etc/openvpn/client/keys/{client_name}.crt"):
        os.remove(f"/etc/openvpn/client/keys/{client_name}.crt")
    if os.path.exists(f"/etc/openvpn/client/keys/{client_name}.key"):
        os.remove(f"/etc/openvpn/client/keys/{client_name}.key")

    print(f"OpenVPN client '{client_name}' successfully deleted")
    os.chdir("/")  # Change back to root


def list_openvpn():
    """Lists OpenVPN client names."""
    print("\nOpenVPN client names:")
    try:
        result = run_command(["ls", "/etc/openvpn/easyrsa3/pki/issued"],
                             capture_output=True,
                             text=True)
        clients = []
        for line in result.stdout.splitlines():
            if line.endswith(".crt") and line != "antizapret-server.crt":
                clients.append(line.replace(".crt", ""))
        for client in sorted(clients):
            print(client)
    except Exception as e:
        print(f"Could not list OpenVPN clients: {e}")


# --- WireGuard Functions ---
def init_wireguard():
    """Initializes WireGuard server keys and configuration."""
    print("\nInitializing WireGuard/AmneziaWG server keys...")
    if not os.path.exists("/etc/wireguard/key"):
        private_key = run_command(["wg", "genkey"],
                                  capture_output=True,
                                  text=True).stdout.strip()
        public_key = run_command(["wg", "pubkey"],
                                 input=private_key,
                                 capture_output=True,
                                 text=True).stdout.strip()

        with open("/etc/wireguard/key", "w") as f:
            f.write(f"PRIVATE_KEY={private_key}\n")
            f.write(f"PUBLIC_KEY={public_key}\n")

        # Prepare variables for rendering WireGuard configs
        render_vars = {
            "PRIVATE_KEY": private_key,
            "PUBLIC_KEY": public_key,
            "SERVER_IP":
            SERVER_IP,  # Ensure SERVER_IP is available for templates
            **setup_config.config,  # Include all setup config variables
        }

        rendered_antizapret_conf = render(
            "/etc/wireguard/templates/antizapret.conf", render_vars)
        with open("/etc/wireguard/antizapret.conf", "w") as f:
            f.write(rendered_antizapret_conf)

        rendered_vpn_conf = render("/etc/wireguard/templates/vpn.conf",
                                   render_vars)
        with open("/etc/wireguard/vpn.conf", "w") as f:
            f.write(rendered_vpn_conf)
        print("WireGuard/AmneziaWG server keys and configs generated.")
    else:
        print("WireGuard/AmneziaWG server keys already exist.")


def add_wireguard(client_name):
    """Adds or recreates a WireGuard client."""
    print(f"\nAdding WireGuard/AmneziaWG client: {client_name}")
    set_server_host_file_name(client_name, setup_config.get("WIREGUARD_HOST"))

    # Load server keys and IPs
    wireguard_key_vars = {}
    if os.path.exists("/etc/wireguard/key"):
        with open("/etc/wireguard/key", "r") as f:
            for line in f:
                if "=" in line:
                    key, value = line.strip().split("=", 1)
                    wireguard_key_vars[key] = value
    else:
        handle_error(
            "N/A",
            "WireGuard key loading",
            "WireGuard server keys not found. Run init_wireguard first.",
        )

    server_private_key = wireguard_key_vars.get("PRIVATE_KEY")
    server_public_key = wireguard_key_vars.get("PUBLIC_KEY")

    ips_content = ""
    if os.path.exists("/etc/wireguard/ips"):
        ips_content = open("/etc/wireguard/ips", "r").read()

    # --- AntiZapret WireGuard ---
    print("Processing AntiZapret WireGuard configuration...")
    antizapret_conf_path = "/etc/wireguard/antizapret.conf"
    client_exists_az = (run_command(
        ["grep", "-q", f"# Client = {client_name}", antizapret_conf_path],
        check=False,
    ).returncode == 0)

    if client_exists_az:
        print(f"Client (AntiZapret) '{client_name}' exists. Recreating...")
        run_command([
            "sed", "-i", f"/# Client = {client_name}/,/^$/d",
            antizapret_conf_path
        ])
        run_command(["sed", "-i", "/^$/d", antizapret_conf_path])

    client_private_key_az = run_command(["wg", "genkey"],
                                        capture_output=True,
                                        text=True).stdout.strip()
    client_public_key_az = run_command(["wg", "pubkey"],
                                       input=client_private_key_az,
                                       capture_output=True,
                                       text=True).stdout.strip()
    client_preshared_key_az = run_command(["wg", "genpsk"],
                                          capture_output=True,
                                          text=True).stdout.strip()

    base_client_ip_az = ""
    with open(antizapret_conf_path, "r") as f:
        for line in f:
            if line.startswith("Address"):
                base_client_ip_az = ".".join(
                    line.split("=")[1].strip().split("/")[0].split(".")[:3])
                break

    found_ip = False
    for i in range(2, 256):
        potential_ip = f"{base_client_ip_az}.{i}"
        grep_result = run_command(
            ["grep", "-q", potential_ip, antizapret_conf_path], check=False)
        if grep_result.returncode != 0:
            client_ip_az = potential_ip
            found_ip = True
            break
    if not found_ip:
        handle_error(
            "N/A",
            "IP assignment",
            "The WireGuard/AmneziaWG subnet can support only 253 clients!",
        )

    new_peer_config_az = f"""# Client = {client_name}
# PrivateKey = {client_private_key_az}
[Peer]
PublicKey = {client_public_key_az}
PresharedKey = {client_preshared_key_az}
AllowedIPs = {client_ip_az}/32
"""
    with open(antizapret_conf_path, "a") as f:
        f.write(new_peer_config_az)

    if (run_command(
        ["systemctl", "is-active", "--quiet", "wg-quick@antizapret"],
            check=False).returncode == 0):
        run_command(
            ["wg", "syncconf", "antizapret", "<(wg-quick strip antizapret)"],
            shell=True)

    client_dir = f"/root/antizapret/client/{client_name}"
    os.makedirs(client_dir, exist_ok=True)
    current_date = datetime.now().strftime("%y-%m-%d")

    render_vars_wg_az = {
        "SERVER_HOST": SERVER_HOST,
        "SERVER_PUBLIC_KEY": server_public_key,
        "CLIENT_PRIVATE_KEY": client_private_key_az,
        "CLIENT_PUBLIC_KEY": client_public_key_az,
        "CLIENT_PRESHARED_KEY": client_preshared_key_az,
        "CLIENT_IP": client_ip_az,
        "IPS": ips_content,
        **setup_config.config,
    }

    rendered_az_wg_conf = render(
        "/etc/wireguard/templates/antizapret-client-wg.conf",
        render_vars_wg_az)
    if "PublicKey = " in rendered_az_wg_conf:
        rendered_az_wg_conf = rendered_az_wg_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}")
    with open(os.path.join(client_dir, f"AZ-WG-{current_date}.conf"),
              "w") as f:
        f.write(rendered_az_wg_conf)

    rendered_az_am_conf = render(
        "/etc/wireguard/templates/antizapret-client-am.conf",
        render_vars_wg_az)
    if "PublicKey = " in rendered_az_am_conf:
        rendered_az_am_conf = rendered_az_am_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}")
    with open(os.path.join(client_dir, f"AZ-AM-{current_date}.conf"),
              "w") as f:
        f.write(rendered_az_am_conf)

    # --- VPN WireGuard ---
    print("Processing VPN WireGuard configuration...")
    vpn_conf_path = "/etc/wireguard/vpn.conf"
    client_exists_vpn = (run_command(
        ["grep", "-q", f"# Client = {client_name}", vpn_conf_path],
        check=False).returncode == 0)

    if client_exists_vpn:
        print(f"Client (VPN) '{client_name}' exists. Recreating...")
        run_command(
            ["sed", "-i", f"/# Client = {client_name}/,/^$/d", vpn_conf_path])
        run_command(["sed", "-i", "/^$/d", vpn_conf_path])

    client_private_key_vpn = run_command(["wg", "genkey"],
                                         capture_output=True,
                                         text=True).stdout.strip()
    client_public_key_vpn = run_command(["wg", "pubkey"],
                                        input=client_private_key_vpn,
                                        capture_output=True,
                                        text=True).stdout.strip()
    client_preshared_key_vpn = run_command(["wg", "genpsk"],
                                           capture_output=True,
                                           text=True).stdout.strip()

    base_client_ip_vpn = ""
    with open(vpn_conf_path, "r") as f:
        for line in f:
            if line.startswith("Address"):
                base_client_ip_vpn = ".".join(
                    line.split("=")[1].strip().split("/")[0].split(".")[:3])
                break

    found_ip = False
    for i in range(2, 256):
        potential_ip = f"{base_client_ip_vpn}.{i}"
        if (run_command(["grep", "-q", potential_ip, vpn_conf_path],
                        check=False).returncode != 0):
            client_ip_vpn = potential_ip
            found_ip = True
            break
    if not found_ip:
        handle_error(
            "N/A",
            "IP assignment",
            "The WireGuard/AmneziaWG subnet can support only 253 clients!",
        )

    new_peer_config_vpn = f"""# Client = {client_name}
# PrivateKey = {client_private_key_vpn}
[Peer]
PublicKey = {client_public_key_vpn}
PresharedKey = {client_preshared_key_vpn}
AllowedIPs = {client_ip_vpn}/32
"""
    with open(vpn_conf_path, "a") as f:
        f.write(new_peer_config_vpn)

    if (run_command(["systemctl", "is-active", "--quiet", "wg-quick@vpn"],
                    check=False).returncode == 0):
        run_command(["wg", "syncconf", "vpn", "<(wg-quick strip vpn)"],
                    shell=True)

    render_vars_wg_vpn = {
        "SERVER_HOST": SERVER_HOST,
        "SERVER_PUBLIC_KEY": server_public_key,
        "CLIENT_PRIVATE_KEY": client_private_key_vpn,
        "CLIENT_PUBLIC_KEY": client_public_key_vpn,
        "CLIENT_PRESHARED_KEY": client_preshared_key_vpn,
        "CLIENT_IP": client_ip_vpn,
        "IPS": ips_content,
        **setup_config.config,
    }

    rendered_gl_wg_conf = render("/etc/wireguard/templates/vpn-client-wg.conf",
                                 render_vars_wg_vpn)
    if "PublicKey = " in rendered_gl_wg_conf:
        rendered_gl_wg_conf = rendered_gl_wg_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}")
    with open(os.path.join(client_dir, f"GL-WG-{current_date}.conf"),
              "w") as f:
        f.write(rendered_gl_wg_conf)

    rendered_gl_am_conf = render("/etc/wireguard/templates/vpn-client-am.conf",
                                 render_vars_wg_vpn)
    if "PublicKey = " in rendered_gl_am_conf:
        rendered_gl_am_conf = rendered_gl_am_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}")
    with open(os.path.join(client_dir, f"GL-AM-{current_date}.conf"),
              "w") as f:
        f.write(rendered_gl_am_conf)

    print(
        f"WireGuard/AmneziaWG profile files (re)created for client '{client_name}' at {client_dir}"
    )
    print(
        "\nAttention! If import fails, shorten profile filename to 32 chars (Windows) or 15 (Linux/Android/iOS), remove parentheses"
    )


def delete_wireguard(client_name):
    """Deletes a WireGuard client."""
    print(f"\nDeleting WireGuard/AmneziaWG client: {client_name}")
    set_server_host_file_name(client_name, setup_config.get("WIREGUARD_HOST"))

    antizapret_conf_path = "/etc/wireguard/antizapret.conf"
    vpn_conf_path = "/etc/wireguard/vpn.conf"

    # Check if client exists in either config
    client_exists_az = (run_command(
        ["grep", "-q", f"# Client = {client_name}", antizapret_conf_path],
        check=False,
    ).returncode == 0)
    client_exists_vpn = (run_command(
        ["grep", "-q", f"# Client = {client_name}", vpn_conf_path],
        check=False).returncode == 0)

    if not (client_exists_az or client_exists_vpn):
        print(
            f"Failed to delete client '{client_name}'! Please check if client exists."
        )
        return  # Don't exit, just inform and return

    # Remove client block from antizapret.conf
    if client_exists_az:
        run_command(
            [
                "sed", "-i", f"/# Client = {client_name}/,/^$/d",
                antizapret_conf_path
            ],
            description=
            f"Deleting client block for {client_name} from {antizapret_conf_path}",
        )
        # Remove empty lines that might result from deletion
        run_command(["sed", "-i", r"/^$/N;/^\\n$/D", antizapret_conf_path])

    # Remove client block from vpn.conf
    if client_exists_vpn:
        run_command(
            ["sed", "-i", f"/# Client = {client_name}/,/^$/d", vpn_conf_path],
            description=
            f"Deleting client block for {client_name} from {vpn_conf_path}",
        )
        # Remove empty lines
        run_command(["sed", "-i", r"/^$/N;/^\\n$/D", vpn_conf_path])

    client_dir = f"/root/antizapret/client/{client_name}"
    if os.path.exists(client_dir):
        shutil.rmtree(client_dir)

    if (run_command(
        ["systemctl", "is-active", "--quiet", "wg-quick@antizapret"],
            check=False).returncode == 0):
        run_command(
            ["wg", "syncconf", "antizapret", "<(wg-quick strip antizapret)"],
            shell=True)

    if (run_command(["systemctl", "is-active", "--quiet", "wg-quick@vpn"],
                    check=False).returncode == 0):
        run_command(["wg", "syncconf", "vpn", "<(wg-quick strip vpn)"],
                    shell=True)

    print(f"WireGuard/AmneziaWG client '{client_name}' successfully deleted")


def delete_all_protocols(client_name, xray_client):
    """Deletes a client across all supported protocols."""
    print(f"\nDeleting client '{client_name}' from all protocols...")
    delete_openvpn(client_name)
    delete_wireguard(client_name)
    handle_remove_user(argparse.Namespace(name=client_name), xray_client)
    print(f"Client '{client_name}' deletion across all protocols completed.")


def list_wireguard():
    """Lists WireGuard client names."""
    print("\nWireGuard/AmneziaWG client names:")
    try:
        # Concatenate content of both files and then process
        antizapret_content = ""
        if os.path.exists("/etc/wireguard/antizapret.conf"):
            with open("/etc/wireguard/antizapret.conf", "r") as f:
                antizapret_content = f.read()
        vpn_content = ""
        if os.path.exists("/etc/wireguard/vpn.conf"):
            with open("/etc/wireguard/vpn.conf", "r") as f:
                vpn_content = f.read()

        combined_content = antizapret_content + "\n" + vpn_content

        clients = set()
        for line in combined_content.splitlines():
            match = re.match(r"^# Client = (.*)", line)
            if match:
                clients.add(match.group(1).strip())

        for client in sorted(list(clients)):
            print(client)
    except Exception as e:
        print(f"Could not list WireGuard clients: {e}")


# --- General Functions ---
def recreate_profiles(xray_client):
    """Recreates all client profile files."""
    print("\nRecreating client profile files...")

    # Clean up existing client directories
    if os.path.exists("/root/antizapret/client"):
        for item in os.listdir("/root/antizapret/client"):
            item_path = os.path.join("/root/antizapret/client", item)
            if os.path.isdir(item_path):
                shutil.rmtree(item_path)
            elif os.path.isfile(item_path):
                os.remove(item_path)
    else:
        os.makedirs("/root/antizapret/client")

    openvpn_client_names = []
    wireguard_client_names = set()
    vless_users = get_all_users_from_db()

    # Get existing OpenVPN client names
    if os.path.isdir("/etc/openvpn/easyrsa3/pki/issued"):
        result = run_command(["ls", "/etc/openvpn/easyrsa3/pki/issued"],
                             capture_output=True,
                             text=True)
        for line in result.stdout.splitlines():
            if line.endswith(".crt") and line != "antizapret-server.crt":
                openvpn_client_names.append(line.replace(".crt", ""))

    # Get existing WireGuard client names
    combined_content = ""
    if os.path.exists("/etc/wireguard/antizapret.conf"):
        with open("/etc/wireguard/antizapret.conf", "r") as f:
            combined_content += f.read() + "\n"
    if os.path.exists("/etc/wireguard/vpn.conf"):
        with open("/etc/wireguard/vpn.conf", "r") as f:
            combined_content += f.read() + "\n"

    for line in combined_content.splitlines():
        match = re.match(r"^# Client = (.*)", line)
        if match:
            wireguard_client_names.add(match.group(1).strip())
    wireguard_client_names = list(wireguard_client_names)

    # Re-add OpenVPN clients
    print("\nRe-adding OpenVPN profiles...\n")
    if openvpn_client_names:
        init_openvpn()
        for client_name in sorted(openvpn_client_names):
            if re.match(r"^[a-zA-Z0-9_-]{1,32}", client_name):
                add_openvpn(client_name, 3650)
                print(
                    f"OpenVPN profile files recreated for client '{client_name}'"
                )
            else:
                print(
                    f"OpenVPN client name '{client_name}' is invalid! No profile files recreated"
                )
    else:
        print("No OpenVPN clients found to re-add.")

    # Re-add WireGuard clients
    print("\nRe-adding WireGuard/AmneziaWG profiles...\n")
    if wireguard_client_names:
        init_wireguard()
        for client_name in sorted(wireguard_client_names):
            if re.match(r"^[a-zA-Z0-9_-]{1,32}", client_name):
                add_wireguard(client_name)
                print(
                    f"WireGuard/AmneziaWG profile files recreated for client '{client_name}'"
                )
            else:
                print(
                    f"WireGuard/AmneziaWG client name '{client_name}' is invalid! No profile files recreated"
                )
    else:
        print("No WireGuard/AmneziaWG clients found to re-add.")
        print("WireGuard/AmneziaWG configuration not found.")
        init_wireguard()
        print("WireGuard/AmneziaWG server keys created.")

    # Re-add VLESS users
    print("\nRe-adding VLESS profiles...\n")
    if vless_users:
        for user in vless_users:
            handle_add_user(argparse.Namespace(name=user['email']),
                            xray_client,
                            force_recreate=True)
            print(f"VLESS profile file recreated for client '{user['email']}'")
    else:
        print("No VLESS users found to re-add.")


def backup_config():
    """Backs up configuration and client data."""
    print("\nBacking up configuration and clients...")
    backup_dir = "/root/antizapret/backup"
    wireguard_backup_dir = os.path.join(backup_dir, "wireguard")
    xray_backup_dir = os.path.join(backup_dir, "xray")

    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)
    os.makedirs(wireguard_backup_dir, exist_ok=True)
    os.makedirs(xray_backup_dir, exist_ok=True)

    # Copy OpenVPN EasyRSA3
    if os.path.exists("/etc/openvpn/easyrsa3"):
        shutil.copytree("/etc/openvpn/easyrsa3",
                        os.path.join(backup_dir, "easyrsa3"))
    else:
        print(
            "Warning: /etc/openvpn/easyrsa3 not found, skipping OpenVPN backup."
        )

    # Copy WireGuard configs and key
    if os.path.exists("/etc/wireguard/antizapret.conf"):
        shutil.copy("/etc/wireguard/antizapret.conf", wireguard_backup_dir)
    if os.path.exists("/etc/wireguard/vpn.conf"):
        shutil.copy("/etc/wireguard/vpn.conf", wireguard_backup_dir)
    if os.path.exists("/etc/wireguard/key"):
        shutil.copy("/etc/wireguard/key", wireguard_backup_dir)
    else:
        print(
            "Warning: WireGuard configuration files or key not found, skipping WireGuard backup."
        )

    # Copy Xray database
    if os.path.exists(DATABASE_NAME):
        shutil.copy(DATABASE_NAME, xray_backup_dir)
    else:
        print(
            f"Warning: Xray database not found at {DATABASE_NAME}, skipping Xray backup."
        )

    # Copy antizapret config
    if os.path.exists("/root/antizapret/config"):
        shutil.copytree("/root/antizapret/config",
                        os.path.join(backup_dir, "config"))
    else:
        print(
            "Warning: /root/antizapret/config not found, skipping antizapret config backup."
        )

    backup_file = f"/root/antizapret/backup-{SERVER_IP}.tar.gz"

    # Create tar.gz archive
    run_command([
        "tar",
        "-czf",
        backup_file,
        "-C",
        backup_dir,
        "easyrsa3",
        "wireguard",
        "xray",
        "config",
    ])

    # Verify tar.gz (optional, but good practice)
    run_command(["tar", "-tzf", backup_file], capture_output=True, text=True)

    shutil.rmtree(backup_dir)
    print(
        f"Backup of configuration and client data (re)created at {backup_file}"
    )


# --- Xray Constants ---
DATABASE_NAME = "/root/bot/x-ui.db"
INBOUND_TAG = "in-vless"
SERVER_CONFIG_PATH = "/root/antizapret/setup"
CLIENT_CONFIG_BASE_PATH = "/root/antizapret/client"

# --- Xray Database Functions ---


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def create_table():
    """Creates the users table if it doesn't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE
            )
            """)
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_email ON users (email)")
        conn.commit()


def add_user_to_db(uuid, email):
    """Adds a user to the SQLite database."""
    try:
        with get_db_connection() as conn:
            conn.execute(
                "INSERT INTO users (uuid, email) VALUES (?, ?)",
                (uuid, email),
            )
            conn.commit()
            print(f"User '{email}' added to database.")
            return True
    except sqlite3.IntegrityError:
        print(f"Error: User with email '{email}' already exists.")
        return False


def get_user_by_email_from_db(email):
    """Retrieves a single user from the database by email."""
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM users WHERE email = ?",
                            (email, )).fetchone()


def remove_user_from_db(uuid):
    """Removes a user from the SQLite database."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE uuid = ?", (uuid, ))
        conn.commit()


def get_all_users_from_db():
    """Retrieves all users from the SQLite database."""
    with get_db_connection() as conn:
        return conn.execute("SELECT * FROM users").fetchall()


# --- Xray & System Functions ---


def get_xray_client(host, port):
    """Returns an XrayClient instance, raising an exception on failure."""
    try:
        return XrayClient(host, port)
    except Exception as e:
        raise ConnectionError(
            f"Error connecting to Xray API on {host}:{port}: {e}")


def get_server_config(path):
    """Reads server configuration from a key=value file."""
    config = {}
    try:
        with open(path, "r") as f:
            for line in f:
                if "=" in line and not line.strip().startswith("#"):
                    key, value = line.split("=", 1)
                    config[key.strip()] = value.strip()
    except FileNotFoundError:
        print(f"Warning: Server config file not found at {path}")
    return config


def generate_client_config(user_id, server_host, public_key, server_names,
                           vless_port, short_id):
    """Generates the client-side VLESS configuration dictionary."""
    return {
        "dns": {
            "servers": ["10.29.0.1"]
        },
        "fakedns": [
            {
                "ipPool": "198.20.0.0/15",
                "poolSize": 128
            },
            {
                "ipPool": "fc00::/64",
                "poolSize": 128
            },
        ],
        "inbounds": [{
            "listen": "127.0.0.1",
            "port": 1080,
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True
            },
            "sniffing": {
                "destOverride": ["http", "tls", "quic"],
                "enabled": True,
                "routeOnly": True,
            },
            "tag": "in-vless",
        }],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [{
                        "address":
                        server_host,
                        "port":
                        int(vless_port),
                        "users": [{
                            "id": user_id,
                            "encryption": "none",
                            "flow": "xtls-rprx-vision",
                        }],
                    }]
                },
                "streamSettings": {
                    "network": "tcp",
                    "realitySettings": {
                        "fingerprint": "chrome",
                        "publicKey": public_key,
                        "serverName": server_names,
                        "shortId": short_id,
                    },
                    "security": "reality",
                    "tcpSettings": {
                        "header": {
                            "type": "none",
                            "request": {
                                "headers": {}
                            }
                        }
                    },
                },
                "tag": "proxy",
            },
            {
                "protocol": "freedom",
                "tag": "direct"
            },
            {
                "protocol": "blackhole",
                "tag": "block"
            },
        ],
        "routing": {
            "domainStrategy":
            "IPOnDemand",
            "rules": [
                {
                    "ip": ["10.30.0.0/15", "10.29.0.1"],
                    "outboundTag": "proxy",
                    "type": "field",
                },
                {
                    "domain": ["geosite:private"],
                    "outboundTag": "direct",
                    "type": "field",
                },
                {
                    "ip": ["0.0.0.0/0"],
                    "outboundTag": "direct",
                    "type": "field"
                },
            ],
        },
    }


# --- Xray Command Handlers ---


def wait_for_xray_api(xray_client, max_retries=10, delay=3):
    print("Waiting for Xray API to be available...")
    for i in range(max_retries):
        try:
            xray_client.get_inbound_download_traffic(INBOUND_TAG)
            print("Xray API is available.")
            return True
        except Exception as e:
            print(
                f"Attempt {i+1}/{max_retries}: Xray API not ready ({e}). Retrying in {delay} seconds..."
            )
            time.sleep(delay)
    print("Failed to connect to Xray API after multiple retries.")
    return False


def handle_add_user(args, xray_client, force_recreate=False):
    email = args.name
    if not email:
        try:
            email = input("Enter user email: ")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    user_id = None
    if not force_recreate:
        user_id = utils.generate_random_user_id()
        if not add_user_to_db(user_id, email):
            return

        xray_success = False
        try:
            if xray_client.add_client(INBOUND_TAG,
                                      user_id,
                                      email,
                                      flow="xtls-rprx-vision"):
                print(f"User '{email}' successfully added to Xray.")
                xray_success = True
            else:
                print(
                    f"Failed to add user '{email}' to Xray. The user may already exist."
                )
        except Exception as e:
            print(f"An exception occurred while adding user to Xray: {e}")

        if not xray_success:
            print("Rolling back database change...")
            remove_user_from_db(user_id)
            return
    else:
        user = get_user_by_email_from_db(email)
        if not user:
            print(
                f"Error: User with email '{email}' not found in the database.")
            return
        user_id = user["uuid"]

    server_config = get_server_config(SERVER_CONFIG_PATH)
    server_host = server_config.get("SERVER_HOST")
    public_key = server_config.get("VLESS_PUBLIC_KEY")
    server_names = server_config.get("VLESS_SERVER_NAMES")
    short_id = server_config.get("VLESS_SHORT_ID")

    if not all([server_host, public_key, server_names, short_id]):
        print("Error: Could not generate client config.")
        print(
            f"Please ensure SERVER_HOST, VLESS_PUBLIC_KEY, VLESS_SERVER_NAMES, and VLESS_SHORT_ID are set in {SERVER_CONFIG_PATH}"
        )
        return

    vless_port = 443

    config = generate_client_config(user_id, server_host, public_key,
                                    server_names, vless_port, short_id)

    client_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", email)
    date_str = datetime.now().strftime("%y-%m-%d")
    dir_path = os.path.join(CLIENT_CONFIG_BASE_PATH, client_name)
    file_path = os.path.join(dir_path, f"AZ-XR-{date_str}.json")

    os.makedirs(dir_path, exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(config, f, indent=4)
    print(f"Client config saved to: {file_path}")


def handle_remove_user(args, xray_client):
    email = args.name
    if not email:
        try:
            email = input("Enter user email: ")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    user_to_remove = get_user_by_email_from_db(email)
    if not user_to_remove:
        print(f"Error: User with email '{email}' not found in the database.")
        return

    try:
        xray_client.remove_client(INBOUND_TAG, email)
        print(f"User '{email}' removed from Xray.")
    except Exception as e:
        print(
            f"Warning: Could not remove user from Xray (user might not exist there): {e}"
        )

    remove_user_from_db(user_to_remove["uuid"])
    print(f"User '{email}' removed from database.")

    client_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", user_to_remove["email"])
    dir_path = os.path.join(CLIENT_CONFIG_BASE_PATH, client_name)
    if os.path.isdir(dir_path):
        try:
            shutil.rmtree(dir_path)
            print(f"Client config directory removed: {dir_path}")
        except OSError as e:
            print(f"Error removing directory {dir_path}: {e}")


def handle_list_users(args, xray_client):
    users = get_all_users_from_db()
    if not users:
        print("No users found in the database.")
        return

    print("\n--- User List ---")
    for i, user in enumerate(users, 1):
        print(f"{i}. Email: {user['email']} | UUID: {user['uuid']}")
    print("-----------------")


def handle_load_all_users(args, xray_client):
    print("Loading all users from database into Xray...")
    users = get_all_users_from_db()
    if not users:
        print("No users found to load.")
        return

    loaded_count = 0
    skipped_count = 0
    for user in users:
        try:
            if xray_client.add_client(INBOUND_TAG,
                                      user["uuid"],
                                      user["email"],
                                      flow="xtls-rprx-vision"):
                print(f"  Loaded user: {user['email']}")
                loaded_count += 1
            else:
                print(
                    f"  Skipping user {user['email']}: already exists on server."
                )
                skipped_count += 1
        except Exception as e:
            print(f"  Error loading user {user['email']}: {e}")
            skipped_count += 1

    print("-" * 40)
    print(
        f"Finished loading users. Loaded: {loaded_count}, Skipped/Errors: {skipped_count}."
    )


# Global variables to mimic shell script's global scope
SERVER_IP = None
SERVER_HOST = None
FILE_NAME = None


def main():
    global setup_config, SERVER_IP

    # Initialize setup config
    try:
        setup_config = SetupConfig()
    except FileNotFoundError as e:
        handle_error("N/A", "SetupConfig initialization", str(e))

    # Set LC_ALL=C (for consistent sorting/locale behavior in subprocesses)
    os.environ["LC_ALL"] = "C"

    # Set server IP
    set_server_ip()

    parser = argparse.ArgumentParser(
        description="Manage VPN clients (OpenVPN, WireGuard/AmneziaWG, VLESS)."
    )
    parser.add_argument("n", nargs="?", type=int, help="Option choice")
    parser.add_argument("name", nargs="?", help="Client name or email")
    parser.add_argument("date",
                        nargs="?",
                        type=int,
                        help="Certificate expiration days (for OpenVPN)")

    args = parser.parse_args()

    option = args.n
    client_name = args.name
    client_cert_expire = args.date

    if not option:
        # Interactive menu
        while True:
            print("\nPlease choose option:")
            print("    1) OpenVPN - Add client/Renew client certificate")
            print("    2) OpenVPN - Delete client")
            print("    3) OpenVPN - List clients")
            print("    4) WireGuard/AmneziaWG - Add client")
            print("    5) WireGuard/AmneziaWG - Delete client")
            print("    6) WireGuard/AmneziaWG - List clients")
            print("    7) VLESS - Add user")
            print("    8) VLESS - Remove user")
            print("    9) VLESS - List users")
            print("    10) VLESS - Load all users from DB to Xray")
            print(
                "    11) Create all VPN client types (OpenVPN, WireGuard and VLESS)"
            )
            print("    12) Delete client from all protocols")
            print("    13) Recreate client profile files")
            print("    14) Backup configuration and clients")
            print("    15) Exit")

            try:
                option_input = input("Option choice [1-15]: ").strip()
                if not option_input:
                    continue
                option = int(option_input)
            except (ValueError, KeyboardInterrupt):
                print("\nExiting...")
                break

            if option == 1:
                client_name = ask_client_name()
                client_cert_expire = ask_client_cert_expire()
                init_openvpn()
                add_openvpn(client_name, client_cert_expire)
            elif option == 2:
                list_openvpn()
                client_name = ask_client_name()
                delete_openvpn(client_name)
            elif option == 3:
                list_openvpn()
            elif option == 4:
                client_name = ask_client_name()
                init_wireguard()
                add_wireguard(client_name)
            elif option == 5:
                list_wireguard()
                client_name = ask_client_name()
                delete_wireguard(client_name)
            elif option == 6:
                list_wireguard()
            elif option in [7, 8, 9, 10, 11, 12, 13]:
                create_table()
                try:
                    xray_client = get_xray_client("127.0.0.1", 10085)
                except ConnectionError as e:
                    print(e)
                    continue
                if not wait_for_xray_api(xray_client):
                    continue

                if option == 7:
                    handle_add_user(argparse.Namespace(name=None), xray_client)
                elif option == 8:
                    handle_remove_user(argparse.Namespace(name=None),
                                       xray_client)
                elif option == 9:
                    handle_list_users(None, xray_client)
                elif option == 10:
                    handle_load_all_users(None, xray_client)
                elif option == 11:
                    client_name = ask_client_name()
                    client_cert_expire = ask_client_cert_expire()
                    init_openvpn()
                    add_openvpn(client_name, client_cert_expire)
                    init_wireguard()
                    add_wireguard(client_name)
                    handle_add_user(argparse.Namespace(name=client_name),
                                    xray_client)
                elif option == 12:
                    client_name = ask_client_name()
                    delete_all_protocols(client_name, xray_client)
                elif option == 13:
                    recreate_profiles(xray_client)
            elif option == 14:
                backup_config()
            elif option == 15:
                print("Exiting...")
                break
            else:
                print("Invalid option selected.")
    else:
        if option == 1:
            init_openvpn()
            add_openvpn(client_name, client_cert_expire)
        elif option == 2:
            delete_openvpn(client_name)
        elif option == 3:
            list_openvpn()
        elif option == 4:
            init_wireguard()
            add_wireguard(client_name)
        elif option == 5:
            delete_wireguard(client_name)
        elif option == 6:
            list_wireguard()
        elif option in [7, 8, 9, 10, 11, 12, 13]:
            create_table()
            try:
                xray_client = get_xray_client("127.0.0.1", 10085)
            except ConnectionError as e:
                print(e)
                return
            if not wait_for_xray_api(xray_client):
                return

            if option == 7:
                handle_add_user(args, xray_client)
            elif option == 8:
                handle_remove_user(args, xray_client)
            elif option == 9:
                handle_list_users(args, xray_client)
            elif option == 10:
                handle_load_all_users(args, xray_client)
            elif option == 11:
                init_openvpn()
                add_openvpn(client_name, client_cert_expire)
                init_wireguard()
                add_wireguard(client_name)
                handle_add_user(args, xray_client)
            elif option == 12:
                delete_all_protocols(client_name, xray_client)
            elif option == 13:
                recreate_profiles(xray_client)
        elif option == 14:
            backup_config()
        else:
            print("Invalid option selected.")


if __name__ == "__main__":
    # Set umask as in the original script
    os.umask(0o022)
    main()
