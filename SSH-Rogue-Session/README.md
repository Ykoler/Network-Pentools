# Network-Pentools
A collection of network attacking and defending tools programmed in Python.

# SSH-Rogue-Session

This project implements a simple SSH server and a script to attack the server using the Terrapin attack to initiate a rogue session.

## Project Structure
```
SSH-Rogue-Session/
├── attacker/
│   ├── attack.py
├── client/
│   ├── known_hosts
│   ├── ssh_client.py
├── requirements.txt
├── server/
│   ├── passwords/
│   │   ├── attacker.passwords
│   │   ├── victim.passwords
│   ├── ssh_host_rsa_key
│   ├── ssh_passwords_manager.py
├── Terrapin Presentation.pptx
```

## Requirements

The project requires the following Python packages:

- `asyncssh==2.13.2`

You can install the required packages using:

```sh
pip install -r requirements.txt
```

## SSH Server

The SSH server is implemented in `ssh_passwords_manager.py`. It stores passwords for users and allows clients to save and retrieve passwords.

### Running the SSH Server

To start the SSH server, run:

```sh
python server/ssh_passwords_manager.py
```

### Command-Line Arguments

- `-p`, `--port`: SSH port to listen on (default: 22)
- `--host-key`: SSH host key (default: `server/ssh_host_rsa_key`)
- `-f`, `--authorized-keys-file`: SSH `authorized_keys` file

## Attacker Script

The attacker script is implemented in `attack.py`. It uses the Terrapin attack to initiate a rogue session.

### Running the Attacker Script

To run the attacker script, use:

```sh
python attacker/attack.py --proxy-port <proxy-port> --server-port <server-port> --server-ip <server-ip>
```

### Command-Line Arguments

- `--proxy-port`: The port number for the proxy server
- `--server-port`: The port number for the server (default: 22)
- `--server-ip`: The IP address of the server (default: `127.0.0.1`)


## Client Script

The client script is implemented in `ssh_client.py`. It connects to the SSH server to save and retrieve passwords.

### Running the Client Script

To run the client script, use:

```sh
python client/ssh_client.py --server-ip <server-ip> --server-port <server-port> --username <username> --password <password> --command <command>
```

### Command-Line Arguments

- `--server-ip`: The IP address of the server (default: `127.0.0.1`)
- `--server-port`: The port number of the server (default: 22)
- `--username`: The username to authenticate with
- `--password`: The password to authenticate with
- `--command`: The command to execute on the server(either `save-password` or `get-passwords`)


## License

This project is licensed under the MIT License.
