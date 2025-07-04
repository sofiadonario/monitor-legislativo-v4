# Docker WSL2 Setup Guide

## Prerequisites
You already have Docker Desktop installed on Windows. Now we need to configure it for WSL2.

## Steps to Enable Docker in WSL2

### 1. Start Docker Desktop on Windows
- Open Docker Desktop from Windows Start Menu
- Wait for Docker to fully start (whale icon in system tray should be steady)

### 2. Configure Docker Desktop for WSL2
1. Right-click Docker Desktop tray icon → Settings
2. Go to "General" tab
3. Ensure "Use the WSL 2 based engine" is checked
4. Go to "Resources" → "WSL Integration"
5. Enable integration with your default WSL2 distro
6. Click "Apply & Restart"

### 3. Verify Docker Works in WSL2
After Docker Desktop restarts, open a new WSL2 terminal and run:
```bash
docker --version
docker-compose --version
```

### 4. Alternative: Install Docker in WSL2 Directly
If the above doesn't work, you can install Docker directly in WSL2:

```bash
# Update packages
sudo apt update

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# Add user to docker group
sudo usermod -aG docker $USER

# Install Docker Compose
sudo apt install docker-compose

# Restart WSL2 or logout/login
```

## Once Docker is Working

Run the backend with:
```bash
# From the project root directory
docker-compose up -d

# To see logs
docker-compose logs -f

# To stop
docker-compose down
```

## Troubleshooting

### If Docker commands fail with permission errors:
```bash
sudo service docker start
sudo chmod 666 /var/run/docker.sock
```

### If ports are already in use:
```bash
# Check what's using the ports
sudo netstat -tulpn | grep -E '(5432|6379|8000)'

# Modify docker-compose.yml to use different ports if needed
```