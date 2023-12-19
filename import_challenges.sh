#!/bin/bash

CHALLENGES_DIR="/opt/ctfcli_project/challenges"

# Change to the ctfcli project directory
cd /opt/ctfcli_project

# Initialize ctfcli project (if not already initialized)
if [ ! -d ".ctf" ]; then
    echo "Initializing ctfcli project..."
    ctf init
else
    echo "ctfcli project already initialized."
fi

echo "About to import challenges..."
# Import the converted challenges using ctfd-cli
CHALLENGES_DIR="/opt/ctfcli_project/challenges"

# Loop through the challenge categories
for category_dir in $CHALLENGES_DIR/*; do
    if [ -d "$category_dir" ]; then
        category_name=$(basename "$category_dir")
        echo "Importing category: $category_name"
        for challenge_dir in $category_dir/*; do
            if [ -d "$challenge_dir" ]; then
                challenge_name=$(basename "$challenge_dir")
                echo "Importing challenge: $challenge_name from $challenge_dir"
                
                # Import the challenge using ctfd-cli
                ctf challenge install "$challenge_dir"

                echo "Tried to install challenge: $category_name/$challenge_name"
            fi
        done
    fi
done
