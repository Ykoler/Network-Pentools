"""
This script implements a simple SSH client.
"""
import argparse
import asyncio
import asyncssh
import sys
import logging


def parse_args():
    """
    Parse command-line arguments.

    Returns:
    argparse.Namespace: The parsed arguments.
    """
    parser = argparse.ArgumentParser(description="Simple SSH client")
    parser.add_argument("-H", "--host", help="Hostname or IP address", default='127.0.0.1')
    parser.add_argument("-p", "--port", help="Port number", default=22, type=int)
    parser.add_argument("-u", "--username", help="Username for SSH login", default="victim")
    parser.add_argument("-P", "--password", help="Password for SSH login", default="secret")
    parser.add_argument("-s", "--save-password", help="Password to save")
    parser.add_argument("-c", "--command", help="Command to execute", required=True,
                        choices=['save_password', 'get_passwords'])

    return parser.parse_args()


def client_start(args):
    """
    Start the SSH client and establish a connection.

    Parameters:
    args (argparse.Namespace): Parsed command-line arguments.
    """
    print(f"Connecting to {args.host}:{args.port} as {args.username}")

    try:
        # Run the asyncio event loop until the run_client coroutine is complete
        asyncio.get_event_loop().run_until_complete(run_client(args.host, args.port, args.username, args.password,
                                                               args.save_password, args.command))
    except (OSError, asyncssh.Error) as exc:
        # Exit with an error message if the SSH connection fails
        sys.exit("SSH connection failed: " + str(exc))


async def run_client(host, port, username, password, save_password, command):
    """
    Run the SSH client and execute the specified command.

    Parameters:
    host (str): Hostname or IP address of the SSH server.
    port (int): Port number of the SSH server.
    username (str): Username for SSH login.
    password (str): Password for SSH login.
    save_password (str): Password to save if the save_password command is specified.
    command (str): Command to execute (save_password or get_passwords).
    """
    async with asyncssh.connect(host=host, port=port, username=username, password=password, known_hosts=None,
                                compression_algs=None) as conn:
        if command == 'save_password':
            if not save_password:
                sys.exit("Error: save_password command requires --save-password argument.")
            # Execute the save_password command on the SSH server
            result = await conn.run(f"save_password {save_password}", check=True)
        elif command == 'get_passwords':
            # Execute the get_passwords command on the SSH server
            result = await conn.run("get_passwords", check=True)

        # Print the command output and error
        print(result.stdout, end="")
        print(result.stderr, end="")


if __name__ == "__main__":
    # Set up logging for debugging purposes
    logging.basicConfig(level=logging.DEBUG)
    asyncssh.set_log_level("DEBUG")
    asyncssh.set_debug_level(2)

    # Parse command-line arguments and start the client
    command_args = parse_args()
    client_start(command_args)
