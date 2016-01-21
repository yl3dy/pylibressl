#!/bin/bash

PACKAGES="digest cipher"

for pkg in $PACKAGES; do
    echo "### Building package $pkg"
    PYTHONPATH='.' python3 cryptomodule/${pkg}/build.py
done
