#!/bin/bash
# Microservice-Vault Uninstall Script
# Run as root or with sudo

set -e

APP_DIR="/opt/microservice-vault"
USER="vault"

echo "=== Uninstalling Microservice-Vault ==="

# Stop services
echo "Stopping services..."
systemctl stop vault-gateway 2>/dev/null || true
systemctl stop vault-tokenize 2>/dev/null || true
systemctl stop vault-crypto 2>/dev/null || true
systemctl stop vault-lock 2>/dev/null || true

# Disable services
echo "Disabling services..."
systemctl disable vault-gateway 2>/dev/null || true
systemctl disable vault-tokenize 2>/dev/null || true
systemctl disable vault-crypto 2>/dev/null || true
systemctl disable vault-lock 2>/dev/null || true

# Remove systemd service files
echo "Removing systemd services..."
rm -f /etc/systemd/system/vault-gateway.service
rm -f /etc/systemd/system/vault-tokenize.service
rm -f /etc/systemd/system/vault-crypto.service
rm -f /etc/systemd/system/vault-lock.service

# Reload systemd
systemctl daemon-reload

# Ask about data removal
read -p "Remove application data? (y/N): " REMOVE_DATA
if [[ "$REMOVE_DATA" =~ ^[Yy]$ ]]; then
    echo "Removing application directory..."
    rm -rf $APP_DIR
    echo "Removing config..."
    rm -rf /etc/microservice-vault
else
    echo "Keeping data at $APP_DIR"
    echo "Removing only binaries..."
    rm -rf $APP_DIR/bin
fi

# Ask about user removal
read -p "Remove vault user? (y/N): " REMOVE_USER
if [[ "$REMOVE_USER" =~ ^[Yy]$ ]]; then
    echo "Removing user $USER..."
    userdel $USER 2>/dev/null || true
fi

echo ""
echo "=== Uninstall Complete ==="
