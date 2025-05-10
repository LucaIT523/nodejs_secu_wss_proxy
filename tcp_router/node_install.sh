#!/bin/bash

# Update package lists
echo "Updating package lists..."
sudo apt update -y

# Install dependencies
echo "Installing dependencies..."
sudo apt install -y build-essential libssl-dev curl

# Download and install NVM
echo "Installing NVM..."
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.3/install.sh | bash

# Load NVM into the current shell session
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && \. "$NVM_DIR/nvm.sh"  # This loads nvm

# Install Node.js version 18
echo "Installing Node.js version 18..."
nvm install 18.10.0

# Use Node.js version 18
nvm use 18.10.0

# Set Node.js 18 as the default version
nvm alias default 18.10.0

npm install -y
