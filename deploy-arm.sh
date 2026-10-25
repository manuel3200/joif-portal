#!/bin/bash
# =======================================================
# Instalador del Portal Central MiVPN / JOIF en Ubuntu ARM
# =======================================================
set -e

echo "[1/4] Instalando paquetes del sistema en ARM..."
apt-get update -y
apt-get install -y curl wget unzip nodejs npm

echo "[2/4] Preparando directorio /opt/mivpn-portal..."
mkdir -p /opt/mivpn-portal
cd /opt/mivpn-portal

if [ -f "/root/central-portal.zip" ]; then
    unzip -o /root/central-portal.zip -d /opt/mivpn-portal
fi

echo "[3/4] Instalando dependencias de Node.js (compilación nativa ARM64)..."
npm install --omit=dev

echo "[4/4] Configurando servicio Systemd..."
cat << 'EOF' > /etc/systemd/system/mivpn-portal.service
[Unit]
Description=MiVPN Central Multi-Server Portal
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mivpn-portal
ExecStart=/usr/bin/node server.js
Restart=always
RestartSec=3
Environment=PORT=3000
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable mivpn-portal
systemctl restart mivpn-portal

# Liberar puertos en firewall
iptables -I INPUT 1 -p tcp --dport 3000 -j ACCEPT 2>/dev/null || true
iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT 2>/dev/null || true
netfilter-persistent save 2>/dev/null || true

echo "=========================================================="
echo "✅ ¡Portal Central instalado y activo en http://TU_IP:3000!"
echo "=========================================================="
