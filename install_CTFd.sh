# Update and Install Curl
apt-get update && apt-get install -y curl

# Add Docker's official GPG key
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -

# Set up the Docker stable repository
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"

# Install Docker
apt-get update
apt-get install -y docker-ce docker-ce-cli containerd.io

# Get the latest Docker Compose release tag
COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Start and enable Docker service
systemctl start docker
systemctl enable docker

# Define the directory containing your docker-compose.yml
SOURCE_DIR=$(cd $(dirname "$0") && pwd)

# Define the destination directory for CTFd
DEST_DIR=/CTFd

# Create the destination directory if it doesn't exist
mkdir -p $DEST_DIR

# Copy the entire contents of the source directory to the destination directory
cp -r $SOURCE_DIR/* $DEST_DIR/

# Start the CTFd services
cd $DEST_DIR
docker-compose build
docker-compose up -d

# Wait for containers to fully start
sleep 30
# Get the local IP address
LOCAL_IP=$(hostname -I | awk '{print $1}')
CTFD_PORT="8000"
CTFD_URL="http://${LOCAL_IP}:${CTFD_PORT}"

echo "HEALTH CHECK 1"
# Health check for CTFd server
CTFD_HOME_CONTENT="$(curl -s http://172.24.128.112:8000/)"
echo $CTFD_HOME_CONTENT
# Determine container name prefix and ensure it's lowercase
CONTAINER_PREFIX=$(basename $(pwd) | tr '[:upper:]' '[:lower:]') # Converts to lowercase

# Copy the DAO.py script and related files into the CTFd container
docker cp $SOURCE_DIR ${CONTAINER_PREFIX}-ctfd-1:/CTFd/

# Get CTFd version from GitHub
CTFD_VERSION=$(curl -s https://api.github.com/repos/CTFd/CTFd/releases/latest | grep 'tag_name' | cut -d\" -f4)

# Get the current time and set end time to 30 days from now using Python
START_TIME=$(python3 -c 'import datetime; print(int(datetime.datetime.now().timestamp()))')
END_TIME=$(python3 -c 'import datetime; print(int((datetime.datetime.now() + datetime.timedelta(days=30)).timestamp()))')

# Replace placeholders in config.csv with actual values
sed -i "s/YOUR_VERSION/$CTFD_VERSION/" $DEST_DIR/embedded_CTFd/config.csv
sed -i "s/YOUR_START_TIMESTAMP/$START_TIME/" $DEST_DIR/embedded_CTFd/config.csv
sed -i "s/YOUR_END_TIMESTAMP/$END_TIME/" $DEST_DIR/embedded_CTFd/config.csv

# Execute the DAO.py script to update the configuration and generate token
docker exec ${CONTAINER_PREFIX}-ctfd-1 python /CTFd/embedded_CTFd/DAO.py --config_csv /CTFd/embedded_CTFd/config.csv

# Extract the admin token for 'OS_Master' from the DAO.py output
OUTPUT==$(docker exec ${CONTAINER_PREFIX}-ctfd-1 python /CTFd/embedded_CTFd/DAO.py --admin_token "OS_Master")
ADMIN_TOKEN=$(echo "$OUTPUT" | grep "Admin token for 'OS_Master':" | cut -d' ' -f5)
echo "admin token"
echo $ADMIN_TOKEN
# If needed, restart the CTFd service to apply configuration changes
docker-compose restart

sleep 30 # Short delay to allow server to restart

# Create the ctfcli INI config file with the CTFd URL and the generated token
echo "[config]" > config.ini
echo "url = ${CTFD_URL}" >> config.ini
echo "access_token = $ADMIN_TOKEN" >> config.ini
echo "[challenges]" >> config.ini

# Copy the config file to the Docker container's ctfcli project directory
docker exec ${CONTAINER_PREFIX}-ctfd-1 mkdir -p /opt/ctfcli_project/.ctf
docker cp config.ini ${CONTAINER_PREFIX}-ctfd-1:/opt/ctfcli_project/.ctf/config

# Convert CTFd export to ctfd-cli format
echo "converting previous CTFd challenges export to cli format..."
docker exec ${CONTAINER_PREFIX}-ctfd-1 python /CTFd/embedded_CTFd/challenge_Export2cli.py /CTFd/embedded_CTFd/CTFd_export /opt/ctfcli_project

# Initialize ctfcli project
#echo "-------------INit-------------"
#docker exec ${CONTAINER_PREFIX}-ctfd-1 bash -c "cd /opt/ctfcli_project && ctf init"
#echo "------------------------------"
#echo "About to import challenges..."
# Copy the import_challenges.sh script to the Docker container
docker cp import_challenges.sh ${CONTAINER_PREFIX}-ctfd-1:/opt/ctfcli_project/

# Execute the script inside the Docker container
docker exec ${CONTAINER_PREFIX}-ctfd-1 /bin/bash /opt/ctfcli_project/import_challenges.sh
