#!/bin/bash

PACKAGES="digest cipher"

echo '### Building core aux module'
PYTHONPATH='.' python3 cryptomodule/build.py

for pkg in $PACKAGES; do
    echo "### Building package $pkg"
    PYTHONPATH='.' python3 cryptomodule/${pkg}/build.py
done
