"""
This script implements a simple SSH server.
It stores passwords for users and allows clients to save and retrieve passwords.
"""

import argparse
import pathlib
import asyncio
import asyncssh
import logging
import sys

# Predefined passwords for users
PASSWORDS = {"victim": "secret", "attacker": "attacker", "username": "password", "example": "example"}
# Dictionary to store paths to authorized keys files for users
AUTHORIZED_KEYS_FILES = {}


def handle_client(process: asyncssh.SSHServerProcess) -> None:
    """
    Handle incoming SSH client connections and execute commands.

    Parameters:
    process (asyncssh.SSHServerProcess): The SSH server process handling the client connection.
    """
    username = process.get_extra_info('username')
    process.stdout.write("Welcome to my SSH server!\n")
    command = process.command.strip()

    if command.startswith("save_password"):
        _, password = command.split(' ', 1)
        save_password(username, password.strip())
        process.stdout.write("Password saved successfully.\n")
    elif command == "get_passwords":
        process.stdout.write(get_passwords(username))
    else:
        process.stdout.write(f"Unsupported command: {command}\n")

    process.exit(0)


def save_password(username, password):
    """
    Save a password for a user.

    Parameters:
    username (str): The username of the client.
    password (str): The password to save.
    """
    filepath = f"passwords/{username}.passwords"
    with open(filepath, "a") as f:
        f.write(f"{password}\n")


def get_passwords(username):
    """
    Retrieve saved passwords for a user.

    Parameters:
    username (str): The username of the client.

    Returns:
    str: The saved passwords or a message indicating no passwords were found.
    """
    filepath = f"passwords/{username}.passwords"
    try:
        with open(filepath, "r") as f:
            passwords = f.readlines()
            return "PASSWORDS:\n" + "\n".join(passwords)
    except FileNotFoundError:
        return "No passwords saved.\n"


class MySSHServer(asyncssh.SSHServer):
    """
    Custom SSH server class to handle authentication and connections.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._logger = logging.getLogger(__name__)
        self._conn = None

    def connection_made(self, conn):
        """
        Called when a new connection is made.

        Parameters:
        conn (asyncssh.SSHServerConnection): The connection object.
        """
        self._conn = conn
        self._logger.info("Connection established!")

    def begin_auth(self, username):
        """
        Begin authentication for a user.

        Parameters:
        username (str): The username of the client.

        Returns:
        bool: True to continue authentication.
        """
        assert self._conn is not None

        try:
            authorized_keys_file = AUTHORIZED_KEYS_FILES[username]
        except KeyError:
            self._logger.debug(f"User {username} has no authorized_keys file.")
            self._logger.debug(f"Users with authorized_keys file: {list(AUTHORIZED_KEYS_FILES.keys())}.")
        else:
            self._logger.debug(f"authorized_keys file for user {username}: {authorized_keys_file}")
            try:
                self._conn.set_authorized_keys(str(authorized_keys_file))
            except IOError:
                self._logger.exception("Error occurred during begin_auth, maybe there is no key for this user.")
                self._logger.debug(f"Falling back to password authentication for user {username}.")
        return True

    def password_auth_supported(self):
        """
        Check if password authentication is supported.

        Returns:
        bool: True if password authentication is supported.
        """
        return bool(PASSWORDS)

    def validate_password(self, username, password):
        """
        Validate the password for a user.

        Parameters:
        username (str): The username of the client.
        password (str): The password provided by the client.

        Returns:
        bool: True if the password is valid, False otherwise.
        """
        self._logger.debug(f"Validating password for user {username}.")
        try:
            expected_password = PASSWORDS[username]
        except KeyError:
            self._logger.debug(f"User {username} has no password.")
            self._logger.debug(f"Users with passwords: {list(PASSWORDS.keys())}.")
        else:
            if password == expected_password:
                self._logger.debug(f"Password for user {username} is correct.")
                return True

        self._logger.debug(f"Password authentication for user {username} failed.")
        return False


async def start_server(port, host_keys):
    """
    Start the SSH server.

    Parameters:
    port (int): The port number to listen on.
    host_keys (list): List of host keys for the server.
    """
    await asyncssh.create_server(MySSHServer, "", port, server_host_keys=host_keys, process_factory=handle_client)


def parse_args():
    """
    Parse command-line arguments.

    Returns:
    argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Start an SSH server.")
    parser.add_argument("-p", "--port", help="SSH port to listen on", default=22, type=int)
    parser.add_argument("--host-key", help="SSH host key",
                        default=pathlib.Path(__file__).parent.joinpath("ssh_host_rsa_key"), type=pathlib.Path)
    parser.add_argument("-f", "--authorized-keys-file", help="SSH authorized_keys file", type=pathlib.Path)

    return parser.parse_args()


def main(args):
    """
    Main entry point for the SSH server.

    Parameters:
    args (argparse.Namespace): Parsed command-line arguments.
    """
    logger = logging.getLogger(__name__)
    logger.info(f"Server starting up on {args.port}...")

    if args.authorized_keys_file is not None:
        logger.info(f"authorized_keys file: {args.authorized_keys_file}")
        AUTHORIZED_KEYS_FILES.update({user: args.authorized_keys_file for user in PASSWORDS.keys()})
    else:
        logger.warning("No authorized_keys file given, publickey auth will not work.")

    if not PASSWORDS and args.authorized_keys_file is None:
        logger.warning("Neither password nor authorized_keys file specified, you won't be able to log in!")

    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(start_server(port=args.port, host_keys=[args.host_key]))
    except (OSError, asyncssh.Error) as exc:
        sys.exit("Error starting server: " + str(exc))
    loop.run_forever()
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_log_level("DEBUG")
    asyncssh.set_debug_level(2)
    command_args = parse_args()
    sys.exit(main(command_args))
