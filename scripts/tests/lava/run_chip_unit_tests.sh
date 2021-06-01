#!/bin/bash

set -xe

# Fix me: Check arguments validity
GITHUB_REPOSITORY=$1
GITHUB_ARTIFACT_NAME=$2
GITHUB_TOKEN=$3

SCRIPT_DIR="$(dirname "${BASH_SOURCE[0]}")" # Get the directory name
SCRIPT_DIR="$(realpath "${SCRIPT_DIR}")"    # Resolve its full path if need be

source $SCRIPT_DIR/common.sh

echo "Downloading artifact: $GITHUB_ARTIFACT_NAME in $GITHUB_REPOSITORY"
download_artifacts $GITHUB_REPOSITORY $GITHUB_ARTIFACT_NAME $GITHUB_TOKEN archive.zip

unzip archive.zip

BINARY_PATH="$PWD/chip-tests.hex"

# mount all boards
for x in {a..z}; do
    if [ -e "/dev/sd${x}" ]; then
        echo "mounting /dev/sd${x}"
        mkdir -p "/mnt/mbed${x}"
        mount "/dev/sd${x}" "/mnt/mbed${x}"
    fi
done

# Go into test folder
cd $SCRIPT_DIR/../../../src/test_driver/mbed/mbed-functional

# Install python requirements
pip install -r requirements.txt

# Find the board id
TID="$(mbedls -u -j | jq -r .[0].target_id)"

# Flash the binary
mbedflash flash -i $BINARY_PATH --tid $TID

# Run tests
python3 -m pytest unit-tests/test_unittests.py
