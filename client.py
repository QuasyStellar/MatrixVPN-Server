#!/usr/bin/env python3
import os
import subprocess
import argparse
import re
import shutil
from datetime import datetime


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
        lsb_release = subprocess.run(
            ["lsb_release", "-ds"], capture_output=True, text=True, check=True
        ).stdout.strip()
        uname_r = subprocess.run(
            ["uname", "-r"], capture_output=True, text=True, check=True
        ).stdout.strip()
        current_time = datetime.now().isoformat(timespec="seconds")
        print(f"{lsb_release} {uname_r} {current_time}")
    except subprocess.CalledProcessError as e:
        print(f"Could not get system info: {e}")
    exit(1)


def run_command(
    command_args, description="", check=True, capture_output=True, text=True, **kwargs
):
    """Helper to run shell commands."""
    print(f"Running: {' '.join(command_args)}")
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
        handle_error(
            "N/A", " ".join(command_args), f"Command not found: {command_args[0]}"
        )
    except Exception as e:
        handle_error(
            "N/A", " ".join(command_args), f"An unexpected error occurred: {e}"
        )


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
    if not client_cert_expire or not (
        client_cert_expire.isdigit() and 1 <= int(client_cert_expire) <= 3650
    ):
        print("\nEnter client certificate expiration days (1-3650):")
        while True:
            client_cert_expire = input("Certificate expiration days: ").strip()
            if client_cert_expire.isdigit() and 1 <= int(client_cert_expire) <= 3650:
                break
            else:
                print(
                    "Invalid expiration days. Please enter a number between 1 and 3650."
                )
    return int(client_cert_expire)


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
            r"inet (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/\d+ scope global", line
        )
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
            # Replace ${VAR_NAME} placeholders
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
    if not (
        os.path.exists("./pki/ca.crt")
        and os.path.exists("./pki/issued/antizapret-server.crt")
        and os.path.exists("./pki/private/antizapret-server.key")
    ):
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
            env={"EASYRSA_CA_EXPIRE": "3650", **os.environ},
        )
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-server-full",
                "antizapret-server",
                "nopass",
            ],
            env={"EASYRSA_CERT_EXPIRE": "3650", **os.environ},
        )
    else:
        print("OpenVPN PKI already initialized.")

    os.makedirs("/etc/openvpn/server/keys", exist_ok=True)
    os.makedirs("/etc/openvpn/client/keys", exist_ok=True)

    # Copy server keys if not present
    if not (
        os.path.exists("/etc/openvpn/server/keys/ca.crt")
        and os.path.exists("/etc/openvpn/server/keys/antizapret-server.crt")
        and os.path.exists("/etc/openvpn/server/keys/antizapret-server.key")
    ):
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
            env={"EASYRSA_CRL_DAYS": "3650", **os.environ},
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

    if not (os.path.exists(client_crt_path) and os.path.exists(client_key_path)):
        print("Client does not exist. Building new client certificate.")
        client_cert_expire_days = ask_client_cert_expire(str(client_cert_expire_days))
        run_command(
            [
                "/usr/share/easy-rsa/easyrsa",
                "--batch",
                "build-client-full",
                client_name,
                "nopass",
            ],
            env={"EASYRSA_CERT_EXPIRE": str(client_cert_expire_days), **os.environ},
        )
    else:
        print("Client with that name already exists!")
        print("Current client certificate expiration period:")
        run_command(["openssl", "x509", "-in", client_crt_path, "-noout", "-dates"])
        print("\nAttention! Certificate renewal is NOT possible after 'notAfter' date")
        client_cert_expire_days = ask_client_cert_expire(str(client_cert_expire_days))
        if client_cert_expire_days != 0:  # 0 means don't renew
            print("Renewing client certificate...")
            os.remove(client_crt_path)
            run_command(
                [
                    "/usr/share/easy-rsa/easyrsa",
                    "--batch",
                    "--days",
                    str(client_cert_expire_days),
                    "sign",
                    "client",
                    client_name,
                ]
            )
            # Remove old client key from client/keys if it exists
            if os.path.exists(f"/etc/openvpn/client/keys/{client_name}.crt"):
                os.remove(f"/etc/openvpn/client/keys/{client_name}.crt")
        else:
            print("Certificate renewal skipped.")

    # Copy client keys
    if not (
        os.path.exists(f"/etc/openvpn/client/keys/{client_name}.crt")
        and os.path.exists(f"/etc/openvpn/client/keys/{client_name}.key")
    ):
        print("Copying client keys...")
        shutil.copy(client_crt_path, f"/etc/openvpn/client/keys/{client_name}.crt")
        shutil.copy(client_key_path, f"/etc/openvpn/client/keys/{client_name}.key")
    else:
        print("Client keys already copied.")

    # Get cert contents
    ca_cert_content = run_command(
        [
            "awk",
            "/-----BEGIN CERTIFICATE-----/{flag=1}/-----END CERTIFICATE-----/{print;flag=0;next}flag",
            "/etc/openvpn/server/keys/ca.crt",
        ]
    ).stdout
    client_cert_content = run_command(
        [
            "awk",
            "/-----BEGIN CERTIFICATE-----/{flag=1}/-----END CERTIFICATE-----/{print;flag=0;next}flag",
            f"/etc/openvpn/client/keys/{client_name}.crt",
        ]
    ).stdout
    client_key_content = run_command(
        ["cat", "--", f"/etc/openvpn/client/keys/{client_name}.key"]
    ).stdout

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

    run_command(["/usr/share/easy-rsa/easyrsa", "--batch", "revoke", client_name])
    run_command(
        ["/usr/share/easy-rsa/easyrsa", "gen-crl"],
        env={"EASYRSA_CRL_DAYS": "3650", **os.environ},
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
        result = run_command(
            ["ls", "/etc/openvpn/easyrsa3/pki/issued"], capture_output=True, text=True
        )
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
        private_key = run_command(
            ["wg", "genkey"], capture_output=True, text=True
        ).stdout.strip()
        public_key = run_command(
            ["wg", "pubkey"], input=private_key, capture_output=True, text=True
        ).stdout.strip()

        with open("/etc/wireguard/key", "w") as f:
            f.write(f"PRIVATE_KEY={private_key}\n")
            f.write(f"PUBLIC_KEY={public_key}\n")

        # Prepare variables for rendering WireGuard configs
        render_vars = {
            "PRIVATE_KEY": private_key,
            "PUBLIC_KEY": public_key,
            "SERVER_IP": SERVER_IP,  # Ensure SERVER_IP is available for templates
            **setup_config.config,  # Include all setup config variables
        }

        rendered_antizapret_conf = render(
            "/etc/wireguard/templates/antizapret.conf", render_vars
        )
        with open("/etc/wireguard/antizapret.conf", "w") as f:
            f.write(rendered_antizapret_conf)

        rendered_vpn_conf = render("/etc/wireguard/templates/vpn.conf", render_vars)
        with open("/etc/wireguard/vpn.conf", "w") as f:
            f.write(rendered_vpn_conf)
        print("WireGuard/AmneziaWG server keys and configs generated.")
    else:
        print("WireGuard/AmneziaWG server keys already exist.")


def add_wireguard(client_name):
    """Adds a WireGuard client."""
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
    client_block_az = ""
    if os.path.exists(antizapret_conf_path):
        with open(antizapret_conf_path, "r") as f:
            content = f.read()
            match = re.search(
                rf"^# Client = {re.escape(client_name)}\n(.*?)^AllowedIPs",
                content,
                re.MULTILINE | re.DOTALL,
            )
            if match:
                client_block_az = match.group(0)

    client_private_key_az = ""
    client_public_key_az = ""
    client_preshared_key_az = ""
    client_ip_az = ""

    if client_block_az:
        print(f"Client (AntiZapret) with name '{client_name}' already exists!")
        client_private_key_az = (
            re.search(r"# PrivateKey = (.*)", client_block_az).group(1).strip()
        )
        client_public_key_az = (
            re.search(r"PublicKey = (.*)", client_block_az).group(1).strip()
        )
        client_preshared_key_az = (
            re.search(r"PresharedKey = (.*)", client_block_az).group(1).strip()
        )
        client_ip_az = (
            re.search(r"AllowedIPs = (.*?)/", client_block_az).group(1).strip()
        )
    else:
        client_private_key_az = run_command(
            ["wg", "genkey"], capture_output=True, text=True
        ).stdout.strip()
        client_public_key_az = run_command(
            ["wg", "pubkey"],
            input=client_private_key_az,
            capture_output=True,
            text=True,
        ).stdout.strip()
        client_preshared_key_az = run_command(
            ["wg", "genpsk"], capture_output=True, text=True
        ).stdout.strip()

        base_client_ip_az = ""
        with open(antizapret_conf_path, "r") as f:
            for line in f:
                if line.startswith("Address"):
                    base_client_ip_az = line.split("=")[1].strip().split("/")[0]
                    base_client_ip_az = ".".join(base_client_ip_az.split(".")[:3])
                    break

        found_ip = False
        for i in range(2, 256):
            potential_ip = f"{base_client_ip_az}.{i}"
            if (
                not run_command(
                    ["grep", "-q", potential_ip, antizapret_conf_path], check=False
                ).returncode
                == 0
            ):
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

        if (
            run_command(
                ["systemctl", "is-active", "--quiet", "wg-quick@antizapret"],
                check=False,
            ).returncode
            == 0
        ):
            run_command(
                ["wg", "syncconf", "antizapret"],
                input=run_command(
                    ["wg-quick", "strip", "antizapret"], capture_output=True, text=True
                ).stdout,
            )

    client_dir = f"/root/antizapret/client/{client_name}"
    os.makedirs(client_dir, exist_ok=True)
    current_date = datetime.now().strftime("%y-%m-%d")

    # Prepare variables for rendering WireGuard client configs
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
        "/etc/wireguard/templates/antizapret-client-wg.conf", render_vars_wg_az
    )
    # Ensure PublicKey is correctly set
    if "PublicKey = " in rendered_az_wg_conf:
        rendered_az_wg_conf = rendered_az_wg_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}"
        )
    with open(os.path.join(client_dir, f"AZ-WG-{current_date}.conf"), "w") as f:
        f.write(rendered_az_wg_conf)

    rendered_az_am_conf = render(
        "/etc/wireguard/templates/antizapret-client-am.conf", render_vars_wg_az
    )
    # Ensure PublicKey is correctly set
    if "PublicKey = " in rendered_az_am_conf:
        rendered_az_am_conf = rendered_az_am_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}"
        )
    with open(os.path.join(client_dir, f"AZ-AM-{current_date}.conf"), "w") as f:
        f.write(rendered_az_am_conf)

    # --- VPN WireGuard ---
    print("Processing VPN WireGuard configuration...")
    vpn_conf_path = "/etc/wireguard/vpn.conf"
    client_block_vpn = ""
    if os.path.exists(vpn_conf_path):
        with open(vpn_conf_path, "r") as f:
            content = f.read()
            match = re.search(
                rf"^# Client = {re.escape(client_name)}\n(.*?)^AllowedIPs",
                content,
                re.MULTILINE | re.DOTALL,
            )
            if match:
                client_block_vpn = match.group(0)

    client_private_key_vpn = ""
    client_public_key_vpn = ""
    client_preshared_key_vpn = ""
    client_ip_vpn = ""

    if client_block_vpn:
        print(f"Client (VPN) with name '{client_name}' already exists!")
        client_private_key_vpn = (
            re.search(r"# PrivateKey = (.*)", client_block_vpn).group(1).strip()
        )
        client_public_key_vpn = (
            re.search(r"PublicKey = (.*)", client_block_vpn).group(1).strip()
        )
        client_preshared_key_vpn = (
            re.search(r"PresharedKey = (.*)", client_block_vpn).group(1).strip()
        )
        client_ip_vpn = (
            re.search(r"AllowedIPs = (.*?)/", client_block_vpn).group(1).strip()
        )
    else:
        client_private_key_vpn = run_command(
            ["wg", "genkey"], capture_output=True, text=True
        ).stdout.strip()
        client_public_key_vpn = run_command(
            ["wg", "pubkey"],
            input=client_private_key_vpn,
            capture_output=True,
            text=True,
        ).stdout.strip()
        client_preshared_key_vpn = run_command(
            ["wg", "genpsk"], capture_output=True, text=True
        ).stdout.strip()

        base_client_ip_vpn = ""
        with open(vpn_conf_path, "r") as f:
            for line in f:
                if line.startswith("Address"):
                    base_client_ip_vpn = line.split("=")[1].strip().split("/")[0]
                    base_client_ip_vpn = ".".join(base_client_ip_vpn.split(".")[:3])
                    break

        found_ip = False
        for i in range(2, 256):
            potential_ip = f"{base_client_ip_vpn}.{i}"
            if (
                not run_command(
                    ["grep", "-q", potential_ip, vpn_conf_path], check=False
                ).returncode
                == 0
            ):
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

        if (
            run_command(
                ["systemctl", "is-active", "--quiet", "wg-quick@vpn"], check=False
            ).returncode
            == 0
        ):
            run_command(
                ["wg", "syncconf", "vpn"],
                input=run_command(
                    ["wg-quick", "strip", "vpn"], capture_output=True, text=True
                ).stdout,
            )

    # Prepare variables for rendering VPN client configs
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

    rendered_gl_wg_conf = render(
        "/etc/wireguard/templates/vpn-client-wg.conf", render_vars_wg_vpn
    )
    # Ensure PublicKey is correctly set
    if "PublicKey = " in rendered_gl_wg_conf:
        rendered_gl_wg_conf = rendered_gl_wg_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}"
        )
    with open(os.path.join(client_dir, f"GL-WG-{current_date}.conf"), "w") as f:
        f.write(rendered_gl_wg_conf)

    rendered_gl_am_conf = render(
        "/etc/wireguard/templates/vpn-client-am.conf", render_vars_wg_vpn
    )
    # Ensure PublicKey is correctly set
    if "PublicKey = " in rendered_gl_am_conf:
        rendered_gl_am_conf = rendered_gl_am_conf.replace(
            "PublicKey = ", f"PublicKey = {server_public_key}"
        )
    with open(os.path.join(client_dir, f"GL-AM-{current_date}.conf"), "w") as f:
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
    client_exists_az = (
        run_command(
            ["grep", "-q", f"# Client = {client_name}", antizapret_conf_path],
            check=False,
        ).returncode
        == 0
    )
    client_exists_vpn = (
        run_command(
            ["grep", "-q", f"# Client = {client_name}", vpn_conf_path], check=False
        ).returncode
        == 0
    )

    if not (client_exists_az or client_exists_vpn):
        print(
            f"Failed to delete client '{client_name}'! Please check if client exists."
        )
        return  # Don't exit, just inform and return

    # Remove client block from antizapret.conf
    if client_exists_az:
        with open(antizapret_conf_path, "r") as f:
            lines = f.readlines()
        new_lines = []
        in_client_block = False
        for line in lines:
            if f"# Client = {client_name}" in line:
                in_client_block = True
            if in_client_block and "AllowedIPs" in line:
                in_client_block = False
                continue  # Skip the AllowedIPs line as well
            if not in_client_block:
                new_lines.append(line)
        with open(antizapret_conf_path, "w") as f:
            f.writelines(new_lines)
            run_command(["sed", "-i", "/^$/N;/^\\n$/D", antizapret_conf_path])

    # Remove client block from vpn.conf
    if client_exists_vpn:
        with open(vpn_conf_path, "r") as f:
            lines = f.readlines()
        new_lines = []
        in_client_block = False
        for line in lines:
            if f"# Client = {client_name}" in line:
                in_client_block = True
            if in_client_block and "AllowedIPs" in line:
                in_client_block = False
                continue  # Skip the AllowedIPs line as well
            if not in_client_block:
                new_lines.append(line)
        with open(vpn_conf_path, "w") as f:
            f.writelines(new_lines)
        # Remove empty lines
        run_command(["sed", "-i", "/^$/N;/^\\n$/D", vpn_conf_path])

    client_dir = f"/root/antizapret/client/{client_name}"
    if os.path.exists(client_dir):
        shutil.rmtree(client_dir)

    if (
        run_command(
            ["systemctl", "is-active", "--quiet", "wg-quick@antizapret"], check=False
        ).returncode
        == 0
    ):
        run_command(
            ["wg", "syncconf", "antizapret"],
            input=run_command(
                ["wg-quick", "strip", "antizapret"], capture_output=True, text=True
            ).stdout,
        )

    if (
        run_command(
            ["systemctl", "is-active", "--quiet", "wg-quick@vpn"], check=False
        ).returncode
        == 0
    ):
        run_command(
            ["wg", "syncconf", "vpn"],
            input=run_command(
                ["wg-quick", "strip", "vpn"], capture_output=True, text=True
            ).stdout,
        )

    print(f"WireGuard/AmneziaWG client '{client_name}' successfully deleted")


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
def recreate_profiles():
    """Recreates all client profile files (excluding VLESS)."""
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
    wireguard_client_names = set()  # Use a set to avoid duplicates

    # Get existing OpenVPN client names
    if os.path.isdir("/etc/openvpn/easyrsa3/pki/issued"):
        result = run_command(
            ["ls", "/etc/openvpn/easyrsa3/pki/issued"], capture_output=True, text=True
        )
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
    wireguard_client_names = list(wireguard_client_names)  # Convert set to list

    # Delete all existing clients
    print("\nDeleting existing OpenVPN clients...")
    for client_name in openvpn_client_names:
        delete_openvpn(client_name)

    print("\nDeleting existing WireGuard/AmneziaWG clients...")
    for client_name in wireguard_client_names:
        delete_wireguard(client_name)

    # Re-add OpenVPN clients
    print("\nRe-adding OpenVPN profiles...\n")  # Added newline for better output
    if openvpn_client_names:
        init_openvpn()
        for client_name in sorted(openvpn_client_names):
            if re.match(r"^[a-zA-Z0-9_-]{1,32}", client_name):
                add_openvpn(client_name, 365)  # Assuming 365 days for re-creation
                print(f"OpenVPN profile files recreated for client '{client_name}'")
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

    # VLESS Reality section is intentionally skipped as per user request.


def backup_config():
    """Backs up configuration and client data."""
    print("\nBacking up configuration and clients...")
    backup_dir = "/root/antizapret/backup"
    wireguard_backup_dir = os.path.join(backup_dir, "wireguard")

    if os.path.exists(backup_dir):
        shutil.rmtree(backup_dir)
    os.makedirs(wireguard_backup_dir, exist_ok=True)

    # Copy OpenVPN EasyRSA3
    if os.path.exists("/etc/openvpn/easyrsa3"):
        shutil.copytree("/etc/openvpn/easyrsa3", os.path.join(backup_dir, "easyrsa3"))
    else:
        print("Warning: /etc/openvpn/easyrsa3 not found, skipping OpenVPN backup.")

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

    # Copy antizapret config
    if os.path.exists("/root/antizapret/config"):
        shutil.copytree("/root/antizapret/config", os.path.join(backup_dir, "config"))
    else:
        print(
            "Warning: /root/antizapret/config not found, skipping antizapret config backup."
        )

    backup_file = f"/root/antizapret/backup-{SERVER_IP}.tar.gz"

    # Create tar.gz archive
    # The original script uses -C /root/antizapret/backup and then lists subdirectories
    # This means the archive will contain easyrsa3/, wireguard/, config/ at its root
    run_command(
        [
            "tar",
            "-czf",
            backup_file,
            "-C",
            backup_dir,
            "easyrsa3",
            "wireguard",
            "config",
        ]
    )

    # Verify tar.gz (optional, but good practice)
    run_command(["tar", "-tzf", backup_file], capture_output=True, text=True)

    shutil.rmtree(backup_dir)
    print(f"Backup of configuration and client data (re)created at {backup_file}")


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
        description="Manage VPN clients (OpenVPN, WireGuard/AmneziaWG)."
    )
    parser.add_argument("option", nargs="?", help="Option choice [1-8]", type=int)
    parser.add_argument("client_name", nargs="?", help="Client name")
    parser.add_argument(
        "client_cert_expire",
        nargs="?",
        help="Certificate expiration days (for OpenVPN)",
        type=int,
    )

    args = parser.parse_args()

    option = args.option
    client_name = args.client_name
    client_cert_expire = args.client_cert_expire

    if not option:
        print("\nPlease choose option:")
        print("    1) OpenVPN - Add client/Renew client certificate")
        print("    2) OpenVPN - Delete client")
        print("    3) OpenVPN - List clients")
        print("    4) WireGuard/AmneziaWG - Add client")
        print("    5) WireGuard/AmneziaWG - Delete client")
        print("    6) WireGuard/AmneziaWG - List clients")
        print("    7) Recreate client profile files")
        print("    8) Backup configuration and clients")
        print("    9) Create all VPN client types (OpenVPN and WireGuard)")

        while True:
            try:
                option_input = input("Option choice [1-8]: ").strip()
                option = int(option_input)
                if 1 <= option <= 9:
                    break
                else:
                    print("Invalid option. Please enter a number between 1 and 8.")
            except ValueError:
                print("Invalid input. Please enter a number.")

    if option == 1:
        print(
            f"OpenVPN - Add client/Renew client certificate {client_name if client_name else ''} {client_cert_expire if client_cert_expire is not None else ''}"
        )
        client_name = ask_client_name(client_name)
        client_cert_expire = ask_client_cert_expire(
            str(client_cert_expire) if client_cert_expire is not None else None
        )
        init_openvpn()
        add_openvpn(client_name, client_cert_expire)
    elif option == 2:
        print(f"OpenVPN - Delete client {client_name if client_name else ''}")
        list_openvpn()
        client_name = ask_client_name(client_name)
        delete_openvpn(client_name)
    elif option == 3:
        print("OpenVPN - List clients")
        list_openvpn()
    elif option == 4:
        print(f"WireGuard/AmneziaWG - Add client {client_name if client_name else ''}")
        client_name = ask_client_name(client_name)
        init_wireguard()
        add_wireguard(client_name)
    elif option == 5:
        print(
            f"WireGuard/AmneziaWG - Delete client {client_name if client_name else ''}"
        )
        list_wireguard()
        client_name = ask_client_name(client_name)
        delete_wireguard(client_name)
    elif option == 6:
        print("WireGuard/AmneziaWG - List clients")
        list_wireguard()
    elif option == 7:
        print("Recreate client profile files")
        recreate_profiles()
    elif option == 8:
        print("Backup configuration and clients")
        backup_config()
    elif option == 9:
        print("Create all VPN client types (OpenVPN and WireGuard)")
        client_name = ask_client_name(client_name)
        client_cert_expire = ask_client_cert_expire(
            str(client_cert_expire) if client_cert_expire is not None else None
        )
        init_openvpn()
        add_openvpn(client_name, client_cert_expire)
        init_wireguard()
        add_wireguard(client_name)
    else:
        print("Invalid option selected.")


if __name__ == "__main__":
    # Set umask as in the original script
    os.umask(0o022)
    main()
