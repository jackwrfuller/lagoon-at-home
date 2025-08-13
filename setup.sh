#!/bin/bash
set -e

# Install k3s
echo "Installing k3s"
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable=traefik --disable=servicelb" sh -
sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config

# increase max number of open files
sudo sysctl fs.inotify.max_user_instances=8192
sudo sysctl fs.inotify.max_user_watches=524288

# Add Helm repos
echo "Adding helm repos"
helm repo add harbor https://helm.goharbor.io
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm repo add stable https://charts.helm.sh/stable
helm repo add bitnami https://charts.bitnami.com/bitnami
helm repo add amazeeio https://amazeeio.github.io/charts/
helm repo add lagoon https://uselagoon.github.io/lagoon-charts/
helm repo add minio https://charts.min.io/
helm repo add nats https://nats-io.github.io/k8s/helm/charts/
helm repo add metallb https://metallb.github.io/metallb
helm repo add jetstack https://charts.jetstack.io
helm repo add jouve https://jouve.github.io/charts/
helm repo add twuni https://helm.twun.io
helm repo add k8up https://k8up-io.github.io/k8up
helm repo add appuio https://charts.appuio.ch
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add headlamp https://kubernetes-sigs.github.io/headlamp/
helm repo update

# Install MetalLB
echo "Installing MetalLB"
helm upgrade --install --create-namespace --namespace metallb-system --wait metallb metallb/metallb
kubectl apply -f config/metallb.yml

echo "Installing Cert Manager"
helm upgrade --install --create-namespace -n cert-manager --wait cert-manager jetstack/cert-manager -f values/cert-manager.yml
kubectl apply -f config/lagoon-issuer.yml

#helm show crds prometheus-community/kube-prometheus-stack | kubectl apply -f -
#
## Install Aergia
#echo "Installing Aergia"
#helm upgrade --install --create-namespace --namespace aergia --wait aergia amazeeio/aergia -f values/aergia.yml

# Install Ingress-Nginx
echo "Installing Ingress-nginx"
helm upgrade --install --create-namespace --namespace ingress-nginx --wait ingress-nginx ingress-nginx/ingress-nginx -f values/ingress-nginx.yml

echo "Install Kube Prometheus Stack"
helm upgrade --install --create-namespace --namespace kube-prometheus --wait kube-prometheus prometheus-community/kube-prometheus-stack -f values/prometheus.yml

# Install Harbor
echo "Installing registry (Harbor)"
helm upgrade --install --create-namespace --namespace registry --wait --version=1.16.2 registry harbor/harbor -f values/harbor.yml

# Install Minio
echo "Installing Minio"
helm upgrade --install --create-namespace --namespace minio --wait minio bitnami/minio -f values/minio.yml

echo "Installing Postgresql"
helm upgrade \
	--install \
	--create-namespace \
	--namespace postgresql \
	--wait \
	--timeout $(TIMEOUT) \
	--set image.tag="14.15.0-debian-12-r1" \
	--set auth.postgresPassword="password"
	--version=16.2.3 \
	postgresql \
	bitnami/postgresql

echo "Installing MariaDB"
helm upgrade \
	--install \
	--create-namespace \
	--namespace mariadb \
	--wait \
	--set auth.rootPassword="password" \
	--version=12.2.9 \
	mariadb \
	bitnami/mariadb

echo "Installing Lagoon Core"
kubectl create namespace lagoon-core
kubectl -n lagoon-core apply -f config/nats-cert.yml
kubectl -n lagoon-core apply -f config/broker-tls.yml
helm upgrade --install --create-namespace --namespace lagoon-core -f values/lagoon-core.yml lagoon-core lagoon/lagoon-core


echo "Installing Lagoon Remote"
kubectl create namespace lagoon
kubectl -n lagoon apply -f config/remote-nats-cert.yml
kubectl -n lagoon apply -f config/remote-cert.yml
kubectl apply -f config/bulk-storage.yml
helm upgrade --install --create-namespace --namespace lagoon -f values/lagoon-remote.yml lagoon-remote lagoon/lagoon-remote


echo "Checking JWT is installed."
if ! command -v jwt >/dev/null 2>&1; then
	echo "JWT not found, installing now..."
	TMPDIR=$(mktemp -d) \
		&& curl -sSL https://github.com/mike-engel/jwt-cli/releases/download/6.2.0/jwt-linux.tar.gz | tar -xzC $TMPDIR \
		&& sudo mv $TMPDIR/jwt /usr/local/bin/jwt \
		&& rm -rf $TMPDIR \
		&& chmod a+x /usr/local/bin/jwt
else
	echo "JWT already installed."
fi

echo "Checking JQ is installed."
if ! command -v jq >/dev/null 2>&1; then
	echo "JQ not found, installing now..."
	sudo apt update && sudo apt install -y jq
else
	echo "JQ already installed."
fi

echo "Obtaining Legacy Token"
JWTUSER=localadmin; \
JWTAUDIENCE=api.dev; \
JWTSECRET=$(kubectl get secret -n lagoon-core lagoon-core-secrets -o json | jq -r '.data.JWTSECRET | @base64d'); \
TOKEN=$(jwt encode --alg HS256 --no-iat --payload role=admin --iss "$JWTUSER" --aud "$JWTAUDIENCE" --sub "$JWTUSER" --secret "$JWTSECRET")
echo "TOKEN: ${TOKEN}"

echo "Create user since api seeding isn't working currently"
QUERY='mutation (
  $email: String!,
  $firstName: String,
  $lastName: String,
  $comment: String,
) {
  addUser(input: {
    email: $email,
    firstName: $firstName,
    lastName: $lastName,
    comment: $comment,
  }) {
    id
    email
    firstName
    lastName
  }
}'

VARIABLES='{
  "email": "jwrf@example.com",
  "firstName": "Jack",
  "lastName": "Fuller",
  "comment": "Created via API",
}'

curl -s -X POST https://api.lagoon.jwrf.au/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg query "$QUERY" --argjson variables "$VARIABLES" \
    '{query: $query, variables: $variables}')"

echo "Add user ssh-key so we can login to LagoonCLI later"
NAME="Starter key"
PUBLIC_KEY=$(cat /home/jwrf/.ssh/id_ed25519.pub)
USER_EMAIL="jwrf@example.com"

read -r -d '' QUERY << EOM
mutation AddKey(\$name: String!, \$publicKey: String!, \$userEmail: String!) {
  addUserSSHPublicKey(input: {
    name: \$name
    publicKey: \$publicKey
    user: {
      email: \$userEmail
    }
  }) {
    id
    name
  }
}
EOM

read -r -d '' VARIABLES << EOM
{
  "name": "$NAME",
  "publicKey": "$PUBLIC_KEY",
  "userEmail": "$USER_EMAIL"
}
EOM

# POST request to Lagoon GraphQL API
curl -s -X POST https://api.lagoon.jwrf.au/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d "$(jq -n --arg query "$QUERY" --argjson variables "$VARIABLES" '{query: $query, variables: $variables}')"

echo "Checking LagoonCLI is installed."
if ! command -v lagoon >/dev/null 2>&1; then
	echo "LagoonCLI not found, installing now..."
	sudo curl -L "https://github.com/uselagoon/lagoon-cli/releases/download/v0.32.0/lagoon-cli-v0.32.0-linux-amd64" \
		-o /usr/local/bin/lagoon \
		&& sudo chmod +x /usr/local/bin/lagoon
else
	echo "LagoonCLI already installed."
fi

echo "Adding cluster to lagoon"
# Requires https://github.com/uselagoon/lagoon-cli/pull/459
lagoon config add \
	--force \
	--graphql https://api.lagoon.jwrf.au/graphql \
	--ui https://dashboard.lagoon.jwrf.au \
	--hostname 192.168.1.241 \
	--lagoon cozone \
	--port 2020 \
	--ssh-key "/home/jwrf/.ssh/id_ed25519"
lagoon config default --lagoon cozone
lagoon login

echo "Configuring deploy targets"
lagoon add organization -O cozone
lagoon add deploytarget \
	--force \
	--name cozone \
	--token $TOKEN \
	--console-url https://172.17.0.1:16643 \
	--router-pattern='${environment}-${project}.app.lagoon.jwrf.au'
DEPLOYTARGET_ID=$(lagoon list deploytargets --output-json | jq -r '.data[0].id')
lagoon add organization-deploytarget -O cozone -D $DEPLOYTARGET_ID















