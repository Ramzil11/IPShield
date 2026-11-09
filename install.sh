#!/bin/bash
set -e

REPO="Ramzil11/IPShield"
APP_NAME="IPShield"
TARGET_DIR="/Applications"

echo "🛡️  Установка ${APP_NAME} для macOS..."

ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
  ARCH_TAG="x64"
  echo "🖥️  Архитектура: Intel (x64)"
else
  ARCH_TAG="arm64"
  echo "🍏  Архитектура: Apple Silicon (arm64)"
fi

TMP_DIR=$(mktemp -d /tmp/ipshield-install.XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "⬇️  Скачивание последней версии для ${ARCH_TAG}..."
LATEST_RELEASE=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null || true)

if [ "$ARCH_TAG" = "arm64" ]; then
  DOWNLOAD_URL=$(echo "$LATEST_RELEASE" | grep -o 'https://[^"]*mac\.zip' | grep 'arm64' | head -n 1)
else
  # Intel x64: ищем x64 архив или любой без arm64
  DOWNLOAD_URL=$(echo "$LATEST_RELEASE" | grep -o 'https://[^"]*mac\.zip' | grep 'x64' | head -n 1)
  if [ -z "$DOWNLOAD_URL" ]; then
    DOWNLOAD_URL=$(echo "$LATEST_RELEASE" | grep -o 'https://[^"]*mac\.zip' | grep -v 'arm64' | head -n 1)
  fi
fi

if [ -z "$DOWNLOAD_URL" ]; then
  DOWNLOAD_URL=$(echo "$LATEST_RELEASE" | grep -o 'https://[^"]*mac\.zip' | head -n 1)
fi

if [ -z "$DOWNLOAD_URL" ]; then
  if [ "$ARCH_TAG" = "arm64" ]; then
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/IPShield-1.0.5-arm64-mac.zip"
  else
    DOWNLOAD_URL="https://github.com/${REPO}/releases/latest/download/IPShield-1.0.5-x64-mac.zip"
  fi
fi

curl -fL -# -o "$TMP_DIR/app.zip" "$DOWNLOAD_URL"

echo "📦 Распаковка в ${TARGET_DIR}..."
ditto -xk "$TMP_DIR/app.zip" "$TMP_DIR/extracted"

APP_PATH=$(find "$TMP_DIR/extracted" -maxdepth 2 -name "${APP_NAME}.app" | head -n 1)
if [ -z "$APP_PATH" ]; then
  echo "❌ Ошибка: пакет ${APP_NAME}.app не найден в архиве"
  exit 1
fi

pkill -f "${APP_NAME}.app" 2>/dev/null || true

rm -rf "${TARGET_DIR}/${APP_NAME}.app"
mv "$APP_PATH" "${TARGET_DIR}/${APP_NAME}.app"

# Снимаем карантин Gatekeeper
xattr -cr "${TARGET_DIR}/${APP_NAME}.app"

echo "✅ ${APP_NAME} успешно установлен в ${TARGET_DIR}/${APP_NAME}.app"
echo "🚀 Запуск..."
open -a "${TARGET_DIR}/${APP_NAME}.app"

