echo getting the docker images needed by clair-scanner ...
#docker pull  arminc/clair-db:latest
docker pull arminc/clair-local-scan
docker run -d --name clair-db arminc/clair-db:latest
docker run -p 6060:6060 --link clair-db:postgres -d --name clair arminc/clair-local-scan:latest
docker stop clair
docker stop clair-db

echo installing clair-scanner ...
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
   wget https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_linux_amd64 -O clair-scanner
   chmod +x clair-scanner
   sudo mv clair-scanner /usr/local/bin
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac OSX
   curl -L  https://github.com/arminc/clair-scanner/releases/download/v12/clair-scanner_darwin_amd64 --output clair-scanner
    chmod +x clair-scanner
    mv clair-scanner /usr/local/bin
fi
echo clair-scanner installed. run it with  clair-scanner




