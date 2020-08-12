#!/usr/bin/env bash

set -euxo pipefail

# Remove every file NOT matching a pattern.
#
# Make sure the enclosing directory doesn't contain these patterns, or
# everything will be kept as is.
#
# Only files are removed to avoid removing a directory first before inspecting
# the files inside.

DIR="$1"

find "$DIR" -type f -not \( \
    -wholename "*azspio*"  -o \
    -wholename "*azure*"   -o \
    -wholename "*sphere*"  -o \
    -wholename "*pluton*"  -o \
    -wholename "*mt3620*"  -o \
    -wholename "*asxipfs*" -o \
    -wholename "*littlefs*" \
    \) \
    -delete
