echo installing snyk
npm install -g snyk
echo installing grype and trivy
if [[ "$OSTYPE" == "linux-gnu"* ]]; then
  sudo curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin
  sudo curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sudo sh -s -- -b /usr/local/bin v0.16.0
elif [[ "$OSTYPE" == "darwin"* ]]; then
    # Mac OSX
    curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin v0.16.0
fi

./install-clair-scanner.sh

