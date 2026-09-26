#!/bin/sh
set -e

case "$1" in
    cli)
        echo "Starting Network Guardian CLI..."
        shift
        exec network-guardian "$@"
        ;;
    dashboard)
        echo "Starting Network Guardian with Dashboard..."
        shift
        exec network-guardian --dashboard "$@"
        ;;
    test)
        echo "Running Network Guardian test suite..."
        exec python -m pytest tests/ -v
        ;;
    *)
        exec "$@"
        ;;
esac
