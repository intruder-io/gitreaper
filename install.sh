#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BINARY="gitreaper"

cd "$(dirname "$0")"

echo "Building $BINARY..."
go build -o "$BINARY" .

echo "Installing to $INSTALL_DIR/$BINARY..."
if [ ! -w "$INSTALL_DIR" ]; then
    sudo install -m 755 "$BINARY" "$INSTALL_DIR/$BINARY"
else
    install -m 755 "$BINARY" "$INSTALL_DIR/$BINARY"
fi

echo "Done. Run: $BINARY --help"
