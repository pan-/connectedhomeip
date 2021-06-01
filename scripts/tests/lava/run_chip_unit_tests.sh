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
ls -la
# cat out.hex
