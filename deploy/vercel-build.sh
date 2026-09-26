#!/bin/sh
set -eu

export VITE_DEFAULT_MOCK=0
export VITE_WS_URL=wss://anveshak-2026-api.onrender.com/ws

npm run build --prefix ui
npm run build --prefix ui-simple
mkdir -p ui/dist/simple
cp -R ui-simple/dist/. ui/dist/simple/
