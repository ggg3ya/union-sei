#!/bin/bash

# ASCII Art
ASCII_ART="

 ▄▀▀▀▀▄    ▄▀▀▀▀▄    ▄▀▀▀▀▄   ▄▀▀▄ ▀▀▄  ▄▀▀█▄  
█         █         █        █   ▀▄ ▄▀ ▐ ▄▀ ▀▄ 
█    ▀▄▄  █    ▀▄▄  █    ▀▄▄ ▐     █     █▄▄▄█ 
█     █ █ █     █ █ █     █ █      █    ▄▀   █ 
▐▀▄▄▄▄▀ ▐ ▐▀▄▄▄▄▀ ▐ ▐▀▄▄▄▄▀ ▐    ▄▀    █   ▄▀  
▐         ▐         ▐            █     ▐   ▐   
                                 ▐             
"

# Function to check if a command exists
command_exists() {
  command -v "$1" >/dev/null 2>&1
}

# Print the ASCII art
echo "$ASCII_ART"

# Function to display X intro and ASCII art
display_x_intro() {
    echo "$ASCII_ART"
    echo ""
    echo "Welcome to the CS Surabaya X Channel!"
    echo "Follow us for updates, tips, and more: https://x.com/0x000123"
    echo "Stay connected with the latest blockchain and crypto insights!"
    echo ""
}

# Function to ask if the user has followed X
ask_follow_x() {
    read -p "Have you already followed on X? (yes/no): " followed
    if [ "${followed,,}" != "yes" ]; then
        echo "Please follow me at https://x.com/0x000123 for the latest updates!"
        read -p "Would you like to continue anyway? (yes/no): " proceed
        if [ "${proceed,,}" != "yes" ]; then
            echo "Exiting... Please follow and try again."
            exit 0
        fi
    else
        echo "Awesome!"
    fi
}

# Check for Node.js and npm
echo "Checking for Node.js and npm..."
if ! command_exists node || ! command_exists npm; then
    echo "Node.js or npm not found. Installing..."
    apt update && apt install -y nodejs npm
    if [ $? -ne 0 ]; then
        echo "Failed to install Node.js and npm. Please install them manually and try again."
        exit 1
    fi
else
    echo "Node.js and npm are already installed."
fi

# Install Node.js dependencies with specific ethers version
echo "Installing required Node.js dependencies..."
npm install ethers@5.7.2 readline-sync axios
if [ $? -ne 0 ]; then
    echo "Failed to install Node.js dependencies. Please install them manually using 'npm install ethers@5.7.2 readline-sync axios'."
    exit 1
fi

# Run npm audit fix to address vulnerabilities (without force to avoid breaking changes)
echo "Running npm audit fix to address vulnerabilities..."
npm audit fix
if [ $? -ne 0 ]; then
    echo "npm audit fix failed. Consider running 'npm audit' for details and fix manually."
fi

# Display ASCII art and X intro
display_x_intro

# Ask if the user has followed X
ask_follow_x

# Run the JavaScript script
echo "Starting the bridging script..."
node sei.js

# Final X reminder
echo ""
echo "Bridging process completed."
echo "Don’t forget to stay updated via our X: https://x.com/0x000123"
