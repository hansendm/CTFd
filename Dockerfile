# Use the CTFd base image
FROM ctfd/ctfd

# Ensure running as root
USER root

# Update packages and install pip
RUN apt-get update && apt-get install -y python3-pip default-mysql-client

# Install required Python libraries
RUN pip install pyyaml pymysql sqlalchemy sqlalchemy-utils ctfcli