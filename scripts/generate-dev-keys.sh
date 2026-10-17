#!/usr/bin/env bash
# Genera el par de claves RSA de desarrollo en src/main/resources/keys/.
# El directorio esta gitignored: ninguna clave se versiona (R-002).
# Uso:  ./scripts/generate-dev-keys.sh   y despues exportar SECURITY_RSA_*_KEY_PATH
set -euo pipefail

cd "$(dirname "$0")/.."
KEYS_DIR="src/main/resources/keys"
mkdir -p "$KEYS_DIR"

openssl genrsa -out "$KEYS_DIR/dev-private.pem" 2048
openssl rsa -in "$KEYS_DIR/dev-private.pem" -pubout -out "$KEYS_DIR/dev-public.pem"

echo "Claves generadas en $KEYS_DIR/"
echo "Para arrancar en local:"
echo "  export SECURITY_RSA_PRIVATE_KEY_PATH=$KEYS_DIR/dev-private.pem"
echo "  export SECURITY_RSA_PUBLIC_KEY_PATH=$KEYS_DIR/dev-public.pem"
echo "  export SUPERADMIN_PASSWORD='<password fuerte>'"
