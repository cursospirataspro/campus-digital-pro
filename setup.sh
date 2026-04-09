#!/bin/bash
# =============================================================================
#  setup.sh — Instalación completa del servidor en Ubuntu 22.04 / 24.04
#
#  Ejecutar como root en un VPS limpio:
#    curl -fsSL https://raw.githubusercontent.com/TU_USUARIO/TU_REPO/main/setup.sh | bash
#  O después de subir el proyecto:
#    chmod +x setup.sh && sudo ./setup.sh
#
#  Qué hace este script:
#    1. Actualiza el sistema
#    2. Instala Node.js 20 LTS
#    3. Instala FFmpeg (para procesar videos)
#    4. Instala PM2 (gestor de procesos 24/7)
#    5. Instala Nginx (proxy reverso + SSL)
#    6. Crea usuario dedicado 'reproductor' (más seguro que correr como root)
#    7. Configura el firewall
#    8. Instala dependencias npm
#    9. Configura PM2 para arrancar al reiniciar
#   10. Configura Nginx
# =============================================================================

set -e  # parar si cualquier comando falla

# ---- Colores ----
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $1"; }
info() { echo -e "${YELLOW}[..] $1${NC}"; }
err()  { echo -e "${RED}[!]${NC} $1"; exit 1; }

[[ $EUID -ne 0 ]] && err "Ejecutar como root: sudo ./setup.sh"

# ============================================================
# PASO 1 — Actualizar sistema
# ============================================================
info "Actualizando sistema..."
apt-get update -q && apt-get upgrade -yq
ok "Sistema actualizado"

# ============================================================
# PASO 2 — Node.js 20 LTS
# ============================================================
info "Instalando Node.js 20 LTS..."
curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
apt-get install -yq nodejs
ok "Node.js $(node -v) instalado"

# ============================================================
# PASO 3 — FFmpeg
# ============================================================
info "Instalando FFmpeg..."
apt-get install -yq ffmpeg
ok "FFmpeg $(ffmpeg -version 2>&1 | head -1 | cut -d' ' -f3) instalado"

# ============================================================
# PASO 4 — PM2 (gestor de procesos 24/7)
# ============================================================
info "Instalando PM2..."
npm install -g pm2 --quiet
ok "PM2 $(pm2 -v) instalado"

# ============================================================
# PASO 5 — Nginx
# ============================================================
info "Instalando Nginx..."
apt-get install -yq nginx
ok "Nginx instalado"

# ============================================================
# PASO 6 — Certbot para SSL gratuito (Let's Encrypt)
# ============================================================
info "Instalando Certbot (SSL)..."
apt-get install -yq certbot python3-certbot-nginx
ok "Certbot instalado"

# ============================================================
# PASO 7 — Crear usuario dedicado
# ============================================================
info "Creando usuario 'reproductor'..."
if ! id "reproductor" &>/dev/null; then
    useradd -m -s /bin/bash reproductor
    ok "Usuario 'reproductor' creado"
else
    ok "Usuario 'reproductor' ya existe"
fi

# ============================================================
# PASO 8 — Directorio de la aplicación
# ============================================================
APP_DIR="/opt/reproductor"
info "Preparando $APP_DIR..."
mkdir -p "$APP_DIR"
mkdir -p "$APP_DIR/data"
mkdir -p "$APP_DIR/logs"
mkdir -p "$APP_DIR/public/hls"
mkdir -p "$APP_DIR/public/js"
chown -R reproductor:reproductor "$APP_DIR"
ok "Directorio preparado"

# ============================================================
# PASO 9 — Firewall
# ============================================================
info "Configurando firewall UFW..."
ufw allow OpenSSH
ufw allow 'Nginx Full'
ufw --force enable
ok "Firewall configurado (SSH + HTTP/HTTPS habilitados)"

# ============================================================
# PASO 10 — Configurar PM2 arranque automático
# ============================================================
info "Configurando arranque automático de PM2..."
PM2_STARTUP=$(pm2 startup systemd -u reproductor --hp /home/reproductor 2>&1 | tail -1)
eval "$PM2_STARTUP" 2>/dev/null || true
ok "PM2 configurado para arrancar al reiniciar"

# ============================================================
# FINALIZADO
# ============================================================
echo ""
echo "============================================================"
echo -e "${GREEN}  INSTALACIÓN COMPLETADA${NC}"
echo "============================================================"
echo ""
echo "  Próximos pasos:"
echo ""
echo "  1. Subir tu proyecto a $APP_DIR"
echo "     rsync -avz --exclude node_modules ./  reproductor@IP:$APP_DIR/"
echo ""
echo "  2. Instalar dependencias npm:"
echo "     cd $APP_DIR && npm install --production"
echo ""
echo "  3. Crear el .env con tus valores reales:"
echo "     nano $APP_DIR/.env"
echo ""
echo "  4. Iniciar el servidor:"
echo "     cd $APP_DIR && pm2 start ecosystem.config.js --env production"
echo "     pm2 save"
echo ""
echo "  5. Configurar Nginx (ya tienes nginx.conf en el proyecto):"
echo "     cp $APP_DIR/nginx.conf /etc/nginx/sites-available/reproductor"
echo "     ln -s /etc/nginx/sites-available/reproductor /etc/nginx/sites-enabled/"
echo "     nano /etc/nginx/sites-available/reproductor  # editar tu dominio"
echo "     nginx -t && systemctl reload nginx"
echo ""
echo "  6. SSL gratuito (reemplaza tudominio.com con el tuyo):"
echo "     certbot --nginx -d tudominio.com"
echo ""
echo "  7. Verifica que todo corre:"
echo "     pm2 status"
echo "     pm2 logs reproductor"
echo ""
