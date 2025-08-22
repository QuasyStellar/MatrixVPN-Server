import json
import os
import re
import shutil
import sqlite3
import time
from datetime import datetime

from xtlsapi import XrayClient, utils


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


# --- Constants ---
DATABASE_NAME = "/root/bot/x-ui.db"
INBOUND_TAG = "in-vless"
SERVER_CONFIG_PATH = "/root/antizapret/setup"
CLIENT_CONFIG_BASE_PATH = "/root/antizapret/client"

# --- Database Functions ---


def get_db_connection():
    """Establishes a connection to the SQLite database."""
    conn = sqlite3.connect(DATABASE_NAME)
    conn.row_factory = sqlite3.Row
    return conn


def create_table():
    """Creates the users table if it doesn't exist."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE
            )
            """
        )
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
        return conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()


def remove_user_from_db(uuid):
    """Removes a user from the SQLite database."""
    with get_db_connection() as conn:
        conn.execute("DELETE FROM users WHERE uuid = ?", (uuid,))
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
        raise ConnectionError(f"Error connecting to Xray API on {host}:{port}: {e}")


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


def generate_client_config(
    user_id, server_host, public_key, server_names, vless_port, short_id
):
    """Generates the client-side VLESS configuration dictionary."""
    return {
        "dns": {"servers": ["10.29.0.1"]},
        "fakedns": [
            {"ipPool": "198.20.0.0/15", "poolSize": 128},
            {"ipPool": "fc00::/64", "poolSize": 128},
        ],
        "inbounds": [
            {
                "listen": "127.0.0.1",
                "port": 1080,
                "protocol": "socks",
                "settings": {"auth": "noauth", "udp": True},
                "sniffing": {
                    "destOverride": ["http", "tls", "quic"],
                    "enabled": True,
                    "routeOnly": True,
                },
                "tag": "in-vless",
            }
        ],
        "outbounds": [
            {
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": server_host,
                            "port": int(vless_port),
                            "users": [
                                {
                                    "id": user_id,
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
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
                        "header": {"type": "none", "request": {"headers": {}}}
                    },
                },
                "tag": "proxy",
            },
            {"protocol": "freedom", "tag": "direct"},
            {"protocol": "blackhole", "tag": "block"},
        ],
        "routing": {
            "domainStrategy": "IPOnDemand",
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
                {"ip": ["0.0.0.0/0"], "outboundTag": "direct", "type": "field"},
            ],
        },
    }


# --- Command Handlers ---


def handle_add_user(args, xray_client):
    if not args.email:
        try:
            args.email = input("Enter user email: ")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    user_id = args.uuid if args.uuid else utils.generate_random_user_id()
    user_email = args.email

    if not add_user_to_db(user_id, user_email):
        return

    xray_success = False
    try:
        if xray_client.add_client(
            INBOUND_TAG, user_id, user_email, flow="xtls-rprx-vision"
        ):
            print(f"User '{user_email}' successfully added to Xray.")
            xray_success = True
        else:
            print(
                f"Failed to add user '{user_email}' to Xray. The user may already exist."
            )
    except Exception as e:
        print(f"An exception occurred while adding user to Xray: {e}")

    if not xray_success:
        print("Rolling back database change...")
        remove_user_from_db(user_id)
        return

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

    # VLESS port is not a critical parameter for client config generation
    vless_port = args.vless_port if hasattr(args, "vless_port") else 443

    config = generate_client_config(
        user_id, server_host, public_key, server_names, vless_port, short_id
    )

    client_name = re.sub(r"[^a-zA-Z0-9_.-]", "_", user_email)
    date_str = datetime.now().strftime("%y-%m-%d")
    dir_path = os.path.join(CLIENT_CONFIG_BASE_PATH, client_name)
    file_path = os.path.join(dir_path, f"AZ-XR-{date_str}.json")

    os.makedirs(dir_path, exist_ok=True)
    with open(file_path, "w") as f:
        json.dump(config, f, indent=4)
    print(f"Client config saved to: {file_path}")


def handle_remove_user(args, xray_client):
    if not args.email:
        try:
            args.email = input("Enter user email: ")
        except KeyboardInterrupt:
            print("\nOperation cancelled.")
            return

    user_to_remove = get_user_by_email_from_db(args.email)
    if not user_to_remove:
        print(f"Error: User with email '{args.email}' not found in the database.")
        return

    try:
        xray_client.remove_client(INBOUND_TAG, args.email)
        print(f"User '{args.email}' removed from Xray.")
    except Exception as e:
        print(
            f"Warning: Could not remove user from Xray (user might not exist there): {e}"
        )

    remove_user_from_db(user_to_remove["uuid"])
    print(f"User '{args.email}' removed from database.")

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
            if xray_client.add_client(
                INBOUND_TAG, user["uuid"], user["email"], flow="xtls-rprx-vision"
            ):
                print(f"  Loaded user: {user['email']}")
                loaded_count += 1
            else:
                print(f"  Skipping user {user['email']}: already exists on server.")
                skipped_count += 1
        except Exception as e:
            print(f"  Error loading user {user['email']}: {e}")
            skipped_count += 1

    print("-" * 40)
    print(
        f"Finished loading users. Loaded: {loaded_count}, Skipped/Errors: {skipped_count}."
    )


# --- Main Execution ---


def main():
    create_table()  # Ensure table exists on script start

    parser = argparse.ArgumentParser(description="Xray VLESS User Management Script")
    parser.add_argument(
        "--xray_host", type=str, default="127.0.0.1", help="Xray API host"
    )
    parser.add_argument("--xray_port", type=int, default=10085, help="Xray API port")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command parsers
    add_parser = subparsers.add_parser("add", help="Add a new VLESS user")
    add_parser.add_argument("--uuid", type=str, help="User UUID (optional)")
    add_parser.add_argument(
        "--email", type=str, help="User email/remark (must be unique)"
    )
    add_parser.add_argument(
        "--vless_port", type=int, default=443, help="(Config) VLESS port"
    )

    remove_parser = subparsers.add_parser("remove", help="Remove a user")
    remove_parser.add_argument("--email", type=str, help="Email of the user to remove")

    subparsers.add_parser("list", help="List all users")
    subparsers.add_parser("load", help="Load all users from DB to Xray")

    args = parser.parse_args()

    try:
        xray_client = get_xray_client(args.xray_host, args.xray_port)
    except ConnectionError as e:
        print(e)
        return

    if not wait_for_xray_api(xray_client):
        return

    handlers = {
        "add": handle_add_user,
        "remove": handle_remove_user,
        "list": handle_list_users,
        "load": handle_load_all_users,
    }

    if args.command:
        handlers[args.command](args, xray_client)
    else:
        # Interactive mode
        while True:
            print("\n--- Xray User Manager ---")
            print("1. Add new user")
            print("2. Remove user")
            print("3. List users")
            print("4. Load all users from DB to Xray")
            print("5. Exit")
            try:
                choice = input("Enter your choice: ")
            except KeyboardInterrupt:
                print("\nExiting...")
                break

            if choice == "1":
                handle_add_user(
                    argparse.Namespace(email=None, uuid=None, vless_port=443),
                    xray_client,
                )
            elif choice == "2":
                handle_remove_user(argparse.Namespace(email=None), xray_client)
            elif choice == "3":
                handle_list_users(None, xray_client)
            elif choice == "4":
                handle_load_all_users(None, xray_client)
            elif choice == "5":
                print("Exiting...")
                break
            else:
                print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
