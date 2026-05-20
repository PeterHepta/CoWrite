#!/bin/bash
# 在临时目录中启动服务，避免污染 build/collab_doc_v2.db
set -e
cd "$(dirname "$0")/.."

BIN="$(pwd)/build/DocServer"
if [ ! -x "$BIN" ]; then
    echo "未找到 $BIN，请先在 build/ 中编译" >&2
    exit 1
fi

TMPDIR=$(mktemp -d -t collab-smoke.XXXXXX)
echo "启动服务于 $TMPDIR"
cd "$TMPDIR"
exec "$BIN"
