# Makefile for Homelab Kubernetes + Lagoon
SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all

KUBECONFIG := $(HOME)/.kube/config

BASE_URL=lagoonat.homes
LAGOON_NETWORK_RANGE="192.168.1.150-192.168.1.160"

.PHONY: all dependencies k3s sysctl helm-repos helm metallb cert-manager ingress homelab prometheus harbor minio postgres mariadb tools lagoon-core lagoon-remote

# --- High-level targets ---
all: dependencies lagoon-core lagoon-remote lagoon-config

dependencies: k3s sysctl helm-repos metallb cert-manager ingress homelab prometheus harbor minio postgres 

# --- Core system setup ---
k3s:
	@echo "Installing k3s"
	curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable=traefik --disable=servicelb" sh -
	sudo mkdir -p $(dir $(KUBECONFIG))
	sudo cp /etc/rancher/k3s/k3s.yaml $(KUBECONFIG)
	sudo chmod 644 $(KUBECONFIG)

sysctl:
	@echo "Configuring sysctl limits"
	sudo sysctl fs.inotify.max_user_instances=8192
	sudo sysctl fs.inotify.max_user_watches=524288

helm-repos: helm
	@echo "Adding helm repos"
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

metallb:
	@echo "Installing MetalLB"
	helm upgrade \
		--install \
		--create-namespace \
		--namespace metallb-system \
		--wait \
		metallb \
		metallb/metallb 
	export LAGOON_NETWORK_RANGE=$(LAGOON_NETWORK_RANGE)
	envsubst < config/metallb.yml.tpl > build/metallb.yml
	kubectl apply -f build/metallb.yml

cert-manager:
	@echo "Installing Cert Manager"
	helm upgrade \
		--install \
		--create-namespace \
		--namespace cert-manager \
		--wait \
		--set installCRDs=true \
		--set ingressShim.defaultIssuerName=letsencrypt-staging \
		--set ingressShim.defaultIssuerKind=ClusterIssuer \
		--set ingressShim.defaultIssuerGroup=cert-manager.io \
		cert-manager \
		jetstack/cert-manager
	kubectl apply -f config/lagoon-issuer-letsencrypt.yml
	kubectl apply -f config/lagoon-issuer-letsencrypt-staging.yml
	kubectl apply -f config/lagoon-issuer-selfsigned.yml

ingress:
	@echo "Installing Ingress Nginx"
	helm upgrade \
		--install \
		--create-namespace \
		--namespace ingress-nginx \
		--wait \
		--set controller.allowSnippetAnnotations=true \
		--set controller.enableAnnotationValidations=false \
		--set controller.service.type=LoadBalancer \
		--set controller.service.nodePorts.http=32080 \
		--set controller.service.nodePorts.https=32443 \
		--set controller.config.annotations-risk-level=Critical \
		--set controller.config.proxy-body-size=0 \
		--set controller.config.hsts=false \
		--set controller.watchIngressWithoutClass=true \
		--set controller.ingressClassResource.default=true \
		--set controller.addHeaders.X-Lagoon="remote>ingress-nginx>\$$namespace:\$$service_name" \
		ingress-nginx \
		ingress-nginx/ingress-nginx

homelab:
	@echo "Applying homelab services"
	kubectl apply -f config/caddy.yml

prometheus:
	@echo "Installing Prometheus Stack"
	helm upgrade --install --create-namespace --namespace kube-prometheus --wait kube-prometheus prometheus-community/kube-prometheus-stack -f values/prometheus.yml

harbor:
	@echo "Installing Harbor registry"
	helm upgrade --install --create-namespace --namespace registry --wait --version=1.16.2 registry harbor/harbor -f values/harbor.yml

minio:
	@echo "Installing Minio"
	export BASE_URL=$(BASE_URL)
	helm upgrade \
		--install \
		--create-namespace \
		--namespace minio \
		--wait \
		--set auth.rootUser=admin,auth.rootPassword=password \
		--set ingress.enabled=true \
		--set ingress.ingressClassName=nginx \
		--set ingress.tls=true \
		--set ingress.hostname="minioapi.lagoon.$(BASE_URL)" \
		--set-string ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-staging \
		--set console.ingress.enabled=true \
		--set console.ingress.ingressClassName=nginx \
		--set console.ingress.tls=true \
		--set console.ingress.hostname="minio.lagoon.$(BASE_URL)" \
		--set-string console.ingress.annotations."cert-manager\.io/cluster-issuer"=letsencrypt-staging \
		minio \
		bitnami/minio

postgres:
	@echo "Installing PostgreSQL"
	helm upgrade --install --create-namespace --namespace postgresql --wait \
		--set image.tag="14.15.0-debian-12-r1" \
		--set auth.postgresPassword="password" \
		--version=16.2.3 \
		postgresql bitnami/postgresql

mariadb:
	@echo "Installing MariaDB"
	helm upgrade --install --create-namespace --namespace mariadb --wait \
		--set auth.rootPassword="password" \
		--version=13.1.3 \
		mariadb bitnami/mariadb

# --- Lagoon components ---
lagoon-core:
	@echo "Installing Lagoon Core"
	kubectl create namespace lagoon-core --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n lagoon-core apply -f config/nats-cert.yml
	kubectl -n lagoon-core apply -f config/broker-tls.yml
	helm upgrade --install --create-namespace --namespace lagoon-core \
		-f values/lagoon-core.yml lagoon-core lagoon/lagoon-core

lagoon-remote:
	@echo "Installing Lagoon Remote"
	kubectl create namespace lagoon --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n lagoon apply -f config/remote-nats-cert.yml
	kubectl -n lagoon apply -f config/remote-cert.yml
	kubectl apply -f config/bulk-storage.yml
	helm upgrade --install --wait --create-namespace --namespace lagoon \
		-f values/lagoon-remote.yml lagoon-remote lagoon/lagoon-remote

# --- Tools ---
lagoon-config: jwt jq lagoon-cli post-install

helm:
	@if ! command -v helm >/dev/null; then \
		echo "Installing Helm"; \
		curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash; \
	else echo "Helm already installed"; fi

jwt:
	@if ! command -v jwt >/dev/null; then \
		echo "Installing jwt-cli"; \
		TMPDIR=$$(mktemp -d); \
		curl -sSL https://github.com/mike-engel/jwt-cli/releases/download/6.2.0/jwt-linux.tar.gz | tar -xzC $$TMPDIR; \
		sudo mv $$TMPDIR/jwt /usr/local/bin/jwt; \
		rm -rf $$TMPDIR; \
		chmod a+x /usr/local/bin/jwt; \
	else echo "jwt-cli already installed"; fi

jq:
	@if ! command -v jq >/dev/null; then \
		echo "Installing jq"; \
		sudo apt update && sudo apt install -y jq; \
	else echo "jq already installed"; fi

lagoon-cli:
	@if ! command -v lagoon >/dev/null; then \
		echo "Installing Lagoon CLI"; \
		sudo curl -L "https://github.com/uselagoon/lagoon-cli/releases/download/v0.32.0/lagoon-cli-v0.32.0-linux-amd64" \
			-o /usr/local/bin/lagoon; \
		sudo chmod +x /usr/local/bin/lagoon; \
	else echo "Lagoon CLI already installed"; fi

# --- Lagoon post-install configuration ---
post-install:
	@echo "Obtaining Legacy Token"
	JWTUSER=localadmin; \
	JWTAUDIENCE=api.dev; \
	JWTSECRET=$$(kubectl get secret -n lagoon-core lagoon-core-secrets -o json | jq -r '.data.JWTSECRET | @base64d'); \
	TOKEN=$$(jwt encode --alg HS256 --no-iat --payload role=admin --iss "$$JWTUSER" --aud "$$JWTAUDIENCE" --sub "$$JWTUSER" --secret "$$JWTSECRET"); \
	echo "TOKEN: $$TOKEN"; \
	\
	echo "Creating user"; \
	QUERY='mutation ($$email: String!, $$firstName: String, $$lastName: String, $$comment: String) { addUser(input: { email: $$email, firstName: $$firstName, lastName: $$lastName, comment: $$comment }) { id email firstName lastName } }'; \
	VARIABLES='{"email": "jwrf@example.com", "firstName": "Jack", "lastName": "Fuller", "comment": "Created via API"}'; \
	curl -s -X POST https://api.lagoon.jwrf.au/graphql \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "$$(jq -n --arg query "$$QUERY" --argjson variables "$$VARIABLES" '{query: $$query, variables: $$variables}')";
	echo "Assigning user as platform owner"; \
		QUERY='mutation ($$user: UserInput!, $$role: PlatformRole!) { addPlatformRoleToUser(user: $$user, role: $$role) { id email platformRoles } }'; \
		VARIABLES='{ "user": { "email": "jwrf@example.com" }, "role": "OWNER" }'; \
	curl -s -X POST https://api.lagoon.jwrf.au/graphql \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "$$(jq -n --arg query "$$QUERY" --argjson variables "$$VARIABLES" '{query: $$query, variables: $$variables}')";
	@echo "Adding SSH Key to user"
	SSH_KEY_NAME="jwrf"
	SSH_KEY_VALUE=$$(cat /home/jwrf/.ssh/id_ed25519.pub)
	USER_EMAIL="jwrf@example.com"
	JSON=$$(printf '{"query":"mutation { addUserSSHPublicKey(input: {name: \\"%s\\", publicKey: \\"%s\\", user: {email: \\"%s\\"}}) { id } }"}' "$$SSH_KEY_NAME" "$$SSH_KEY_VALUE" "$$USER_EMAIL")
	curl -s -X POST https://api.lagoon.jwrf.au/graphql \
	  -H 'Content-Type: application/json' \
	  -H "Authorization: Bearer $$TOKEN" \
	  -d "$$JSON"
	KEYCLOAK_URL="https://keycloak.lagoon.jwrf.au"
	KEYCLOAK_TOKEN=$$(curl -s -X POST "$${KEYCLOAK_URL}/auth/realms/master/protocol/openid-connect/token" \
	  -d "grant_type=client_credentials" \
	  -d "client_id=admin-api" \
	  -d "client_secret=$$(kubectl -n lagoon-core get secret lagoon-core-keycloak -o jsonpath="{.data.KEYCLOAK_ADMIN_API_CLIENT_SECRET}" | base64 --decode)" | jq -r '.access_token')
	INITIAL_USER_EMAIL=jwrf@example.com
	INITIAL_USER_PASSWORD="abcqq"
	@echo "Looking up user ID for email: $$INITIAL_USER_EMAIL"
	USER_JSON=$$(curl -s -H "Authorization: Bearer $$KEYCLOAK_TOKEN" \
		-H "Content-Type: application/json" \
		"$${KEYCLOAK_URL}/auth/admin/realms/lagoon/users?email=$${INITIAL_USER_EMAIL}"); \
	USER_ID=$$(echo $$USER_JSON | jq -r '.[0].id'); \
	if [ -z "$$USER_ID" ]; then \
		echo "User not found"; \
		exit 1; \
	fi; \
	echo "Resetting password for user ID $$USER_ID"; \
	curl -s -X PUT \
		-H "Authorization: Bearer $$KEYCLOAK_TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"type": "password", "value": "'"$$INITIAL_USER_PASSWORD"'", "temporary": false}' \
		"$${KEYCLOAK_URL}/auth/admin/realms/lagoon/users/$$USER_ID/reset-password"
	@echo "Adding cluster to Lagoon"
	lagoon config add \
		--force \
		--graphql https://api.lagoon.jwrf.au/graphql \
		--ui https://dashboard.lagoon.jwrf.au \
		--hostname $$(kubectl get svc -n lagoon-core lagoon-core-ssh -o jsonpath='{.status.loadBalancer.ingress[0].ip}')  \
		--lagoon cozone \
		--port 2020 \
		--ssh-key "/home/jwrf/.ssh/id_ed25519"
	lagoon config default --lagoon cozone
	lagoon login
	@echo "Configuring deploy targets"
	@if lagoon list organizations --output-json | jq -e '.data[] | select(.name=="cozone")' >/dev/null; then \
	  echo "Organization cozone already exists"; \
	else \
	  echo "Adding organization cozone"; \
	  lagoon add organization --force -O cozone; \
	fi
	# Check if deploytarget "cozone" exists
	if lagoon list deploytargets --output-json | jq -e '.data // [] | .[] | select(.name=="cozone")' >/dev/null; then
	  echo "Deploytarget 'cozone' already exists"
	else
	  echo "Creating deploytarget 'cozone'"
	  lagoon add deploytarget \
	    --name cozone \
	    --force \
	    --token "$$TOKEN" \
	    --console-url https://172.17.0.1:16643 \
	    --router-pattern='$${environment}-$${project}.app.lagoon.jwrf.au'
	fi
	# Grab its ID
	DEPLOYTARGET_ID=$$(lagoon list deploytargets --output-json | jq -r '.data[] | select(.name=="cozone") | .id')
	# Check if org is already linked to deploytarget
	if lagoon list organization-deploytargets -O cozone --output-json | jq -e --arg id "$$DEPLOYTARGET_ID" '.data[] | select(.id==$$id)' >/dev/null; then
	  echo "Deploytarget 'cozone' already linked to organization 'cozone'"
	else
	  echo "Linking deploytarget to organization"
	  lagoon add organization-deploytarget -O cozone -D "$$DEPLOYTARGET_ID"
	fi

# --- Cleanup ---
clean:
	@echo "Not implemented: cleanup of resources"

