#!/bin/sh

# Check if the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root. Exiting..."
    exit 1
fi

# Generate certificates signed by the fictional CA (if they don't exist)
mkdir -p certs
if [ ! -f certs/key.pem ] || [ ! -f certs/cert.pem ]; then
  echo "Generating certificates signed by the fictional CA..."
  openssl genrsa -out ca.key 4096
  openssl req -new -x509 -days 365 -key ca.key -out ca.crt -subj "/C=PL/ST=Mazovian/L=Warsaw/O=Certifying Authority/CN=SSL CA"
  openssl req -new -key ca.key -out cert.csr -subj "/C=PL/ST=Mazovian/L=Warsaw/O=Warsaw University of Technology/OU=Electrical Department/CN=safetweet.com"
  sh sign.sh cert.csr

  # Moving the necessary files to the certs directory
  mv ca.key certs/key.pem
  mv cert.crt certs/cert.pem

  # Clean up
  rm ca.crt ca.db.index ca.db.index.attr ca.db.index.attr.old ca.db.serial cert.csr 2>/dev/null
  rm -r ca.db.certs 2>/dev/null
fi

# Run the container
docker-compose up --build