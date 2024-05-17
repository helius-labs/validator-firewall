#!/bin/bash

# Function to check if a command exists
command_exists () {
    command -v "$1" &> /dev/null
}

# Check if Cargo is installed
if ! command_exists cargo; then
    echo "Cargo could not be found. Please install Rust and Cargo."
    exit 1
fi

# Build the eBPF binary
echo "Running 'cargo xtask build-ebpf --release'..."
if ! cargo xtask build-ebpf --release; then
    echo "Command 'cargo xtask build-ebpf --release' failed to execute."
    exit 1
fi

# Build userspace
echo "Running 'cargo build --release'..."
if ! cargo build --release; then
    echo "Command 'cargo build --release' failed to execute."
    exit 1
fi

# Install binary
BINARY_PATH="target/release/validator-firewall"
if [ -f "$BINARY_PATH" ]; then
    echo "Copying the binary to /usr/local/sbin..."
    sudo cp "$BINARY_PATH" /usr/local/sbin/
else
    echo "Binary file 'validator-firewall' not found."
    exit 1
fi

# Create config dir
echo "Creating directory /etc/validator-firewall/..."
sudo mkdir -p /etc/validator-firewall/

# Create exmaple static overrides file
STATIC_OVERRIDES_FILE="/etc/validator-firewall/static_overrides.yml"
echo "Creating static_overrides.yml file..."
sudo bash -c "cat > $STATIC_OVERRIDES_FILE" <<EOL
allow:
  - name: example_node
    ip: 1.2.3.4
deny:
  - name: spammer_node
    ip: 1.2.3.6
EOL

# Prompt for interface to filter on
while true; do
    read -p "Enter the network interface to run on (e.g., eth0): " interface
    if ip link show "$interface" &> /dev/null; then
        echo "Interface $interface found."
        break
    else
        echo "Interface $interface does not exist. Please enter a valid interface."
    fi
done

# Create a template systemd unit file
SYSTEMD_FILE="/etc/systemd/system/validator-firewall.service"
echo "Creating systemd unit file..."
sudo bash -c "cat > $SYSTEMD_FILE" <<EOL
[Unit]
Description=Validator Firewall Service
After=network.target

[Service]
Environment=RUST_LOG=info
ExecStart=/usr/local/sbin/validator-firewall --iface $interface --static-overrides $STATIC_OVERRIDES_FILE
Restart=always

[Install]
WantedBy=multi-user.target
EOL

# Reload systemd daemon and enable the service
echo "Reloading systemd daemon..."
sudo systemctl daemon-reload

echo "Enabling validator-firewall service..."
sudo systemctl enable validator-firewall.service

# Prompt whether to start the service
read -p "Do you want to start the validator-firewall service now? (y/n): " start_service

if [[ "$start_service" =~ ^[Yy]$ ]]; then
    echo "Starting validator-firewall service..."
    sudo systemctl start validator-firewall.service
    echo "Service started."
else
    echo "You can start the service later by running: sudo systemctl start validator-firewall.service"
fi

echo "Setup complete!\n"
echo "Configuration file location: $STATIC_OVERRIDES_FILE"
echo "To monitor the output of the validator-firewall service, use the following command:"
echo "sudo journalctl -u validator-firewall.service -f"
