#!/bin/bash
# Microservice-Vault Installation Script
# Run as root or with sudo

set -e

APP_DIR="/opt/microservice-vault"
USER="vault"
GROUP="vault"

echo "=== Installing Microservice-Vault ==="

# Create user and group
if ! id "$USER" &>/dev/null; then
    echo "Creating user $USER..."
    useradd -r -s /bin/false $USER
fi

# Create directories
echo "Creating directories..."
mkdir -p $APP_DIR/bin
mkdir -p $APP_DIR/data
mkdir -p $APP_DIR/logs
mkdir -p /etc/microservice-vault

# Copy binaries
echo "Copying binaries..."
cp bin/* $APP_DIR/bin/
chmod +x $APP_DIR/bin/*

# Copy environment files
echo "Copying config..."
cp env/* /etc/microservice-vault/

# Copy systemd services
echo "Installing systemd services..."
cp systemd/*.service /etc/systemd/system/

# Set permissions
chown -R $USER:$GROUP $APP_DIR
chown -R $USER:$GROUP /etc/microservice-vault

# Reload systemd
systemctl daemon-reload

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Start services with:"
echo "  systemctl start vault-lock"
echo "  systemctl start vault-crypto"
echo "  systemctl start vault-tokenize"
echo "  systemctl start vault-gateway"
echo ""
echo "Enable on boot:"
echo "  systemctl enable vault-lock vault-crypto vault-tokenize vault-gateway"
echo ""
echo "Check status:"
echo "  systemctl status vault-*"
