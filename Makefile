# Makefile for Homelab Kubernetes + Lagoon
SHELL := /bin/bash
.ONESHELL:
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := all

KUBECONFIG=$(HOME)/.kube/config
KUBECTL=kubectl

BASE_URL=192.168.1.150.nip.io
LAGOON_NETWORK_RANGE="192.168.1.150-192.168.1.160"
CLUSTER_ISSUER=selfsigned-issuer

MINIO_USERNAME=admin
MINIO_PASSWORD=password
SEED_USERNAME=jwrf@example.com
SEED_PASSWORD=password
SEED_ORG=cozone

.PHONY: basic all dependencies k3s sysctl helm-repos helm metallb cert-manager ingress homelab prometheus harbor minio postgres mariadb tools lagoon-core lagoon-remote

# --- High-level targets ---
basic: core-dependencies lagoon-core lagoon-remote lagoon-config

all: core-dependencies extras lagoon-core lagoon-remote lagoon-config

core-dependencies: k3s sysctl helm-repos metallb cert-manager ingress registry minio

extras: homelab prometheus postgres 

# --- Core system setup ---
k3s:
	@echo "Installing k3s"
	export BASE_URL=$(BASE_URL)
	curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="server --disable=traefik --disable=servicelb" sh -
	sudo mkdir -p $(dir $(KUBECONFIG))
	sudo cp /etc/rancher/k3s/k3s.yaml $(KUBECONFIG)
	sudo chmod 644 $(KUBECONFIG)
	envsubst < config/k3s.yml.tpl > /tmp/registries.yaml
	sudo mv /tmp/registries.yaml /etc/rancher/k3s/registries.yaml
	sudo systemctl restart k3s

sysctl:
	@echo "Configuring sysctl limits"
	sudo sysctl fs.inotify.max_user_instances=8192
	sudo sysctl fs.inotify.max_user_watches=524288

helm-repos: helm
	@echo "Adding helm repos"
	helm repo add harbor https://helm.goharbor.io
	helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
	helm repo add stable https://charts.helm.sh/stable
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
	export CLUSTER_ISSUER=$(CLUSTER_ISSUER)
	helm upgrade \
		--install \
		--create-namespace \
		--namespace cert-manager \
		--wait \
		--set installCRDs=true \
		--set ingressShim.defaultIssuerName=$(CLUSTER_ISSUER) \
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
	helm upgrade \
		--install \
		--create-namespace \
		--namespace kube-prometheus \
		--wait \
		kube-prometheus \
		prometheus-community/kube-prometheus-stack \
		-f values/prometheus.yml

harbor:
	@echo "Installing Harbor registry"
	export BASE_URL=$(BASE_URL)
	export CLUSTER_ISSUER=$(CLUSTER_ISSUER)
	helm upgrade \
		--install \
		--create-namespace \
		--namespace harbor \
		--wait \
		--version=1.16.2 \
		--set expose.ingress.className=nginx \
                --set-string expose.ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-buffering"="off" \
                --set-string expose.ingress.annotations."nginx\.ingress\.kubernetes\.io/proxy-request-buffering"="off" \
                --set-string expose.ingress.annotations."nginx\.ingress\.kubernetes\.io/ssl-redirect"="false" \
                --set expose.ingress.hosts.core="harbor.$(BASE_URL)" \
                --set expose.tls.enabled=false \
                --set externalURL="http://harbor.$(BASE_URL)" \
                --set harborAdminPassword=password \
                --set chartmuseum.enabled=false \
                --set clair.enabled=false \
                --set notary.enabled=false \
                --set trivy.enabled=false \
                --set jobservice.jobLogger=stdout \
                --set registry.relativeurls=true \
		harbor \
		harbor/harbor \

registry:
	@echo "Installing unauthenticated registry"
	export BASE_URL=$(BASE_URL)
	export CLUSTER_ISSUER=$(CLUSTER_ISSUER)
	helm upgrade \
		--install \
		--create-namespace \
		--namespace registry \
		--wait \
		--set ingress.enabled=true \
		--set "ingress.hosts[0]=registry.$$($(KUBECTL) -n ingress-nginx get services ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}').nip.io" \
		--set ingress.path="/" \
		--set persistence.enabled=true \
		--version=2.2.3 \
		registry \
		twuni/docker-registry

minio:
	@echo "Installing Minio"
	export BASE_URL=$(BASE_URL)
	export CLUSTER_ISSUER=$(CLUSTER_ISSUER)
	helm upgrade \
		--install \
		--create-namespace \
		--namespace minio \
		--wait \
		--set auth.rootUser=$(MINIO_USERNAME),auth.rootPassword=$(MINIO_PASSWORD) \
		--set consoleIngress.enabled=true \
		--set consoleIngress.hosts[0].host="minio.$(BASE_URL)" \
		--set consoleIngress.hosts[0].paths[0].path="/" \
		--set consoleIngress.hosts[0].paths[0].pathType=Prefix \
		--set ingress.enabled=true \
		--set ingress.hosts[0].host=minio-api.$(BASE_URL) \
		--set ingress.hosts[0].paths[0].path="/" \
		--set ingress.hosts[0].paths[0].pathType=Prefix \
		--set-string ingress.annotations."cert-manager\.io/cluster-issuer"=$(CLUSTER_ISSUER) \
		--set-string consoleIngress.annotations."cert-manager\.io/cluster-issuer"=$(CLUSTER_ISSUER) \
		minio \
		oci://registry-1.docker.io/cloudpirates/minio
	$(KUBECTL) -n minio exec -it $$($(KUBECTL) -n minio  get pod -l app.kubernetes.io/name=minio -o jsonpath="{.items[0].metadata.name}") -- sh -c 'mc alias set local http://localhost:9000 $(MINIO_USERNAME) $(MINIO_PASSWORD) && mc mb local/lagoon-files && mc mb local/restores' || true

postgres:
	@echo "Installing PostgreSQL"
	helm upgrade \
		--install \
		--create-namespace \
		--namespace postgresql \
		--wait \
		--set image.tag="14.15.0-debian-12-r1" \
		--set auth.postgresPassword="password" \
		--version=16.2.3 \
		postgresql \
		bitnami/postgresql

mariadb:
	@echo "Installing MariaDB"
	helm upgrade \
		--install \
		--create-namespace \
		--namespace mariadb \
		--wait \
		--set auth.rootPassword="password" \
		--version=13.1.3 \
		mariadb \
		bitnami/mariadb

# --- Lagoon components ---
lagoon-core:
	@echo "Installing Lagoon Core"
	kubectl create namespace lagoon-core --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n lagoon-core apply -f config/nats-cert.yml
	kubectl -n lagoon-core apply -f config/broker-tls.yml
	helm upgrade \
	    --install \
	    --create-namespace \
	    --namespace lagoon-core \
	    --set lagoonSeedUsername="$(SEED_USERNAME)" \
            --set lagoonSeedPassword=$(SEED_PASSWORD) \
            --set lagoonSeedOrganization=$(SEED_ORG) \
	    --set lagoonAPIURL="https://api.$(BASE_URL)/graphql" \
            --set keycloakFrontEndURL="https://keycloak.$(BASE_URL)" \
            --set lagoonUIURL="https://dashboard.$(BASE_URL)" \
	    --set harborURL="http://harbor.$(BASE_URL)" \
	    --set harborAdminPassword=password \
	    --set s3BAASAccessKeyID=admin \
            --set s3BAASSecretAccessKey=password \
            --set s3FilesAccessKeyID=admin \
            --set s3FilesSecretAccessKey=password \
            --set s3FilesBucket=lagoon-files \
            --set s3FilesHost="https://minioapi.$(BASE_URL)" \
	    --set elasticsearchURL="not-real-but-necessary.example.com" \
	    --set kibanaURL="not-real-but-necessary.example.com" \
	    --set keycloak.serviceMonitor.enabled=false \
	    --set broker.serviceMonitor.enabled=false \
	    --set drushAlias.enabled=false \
	    --set backupHandler.enabled=false \
	    --set api.ingress.enabled=true \
            --set api.ingress.hosts[0].host="api.$(BASE_URL)" \
            --set api.ingress.hosts[0].paths[0]="/" \
            --set ui.ingress.enabled=true \
            --set ui.ingress.hosts[0].host="dashboard.$(BASE_URL)" \
            --set ui.ingress.hosts[0].paths[0]="/" \
	    --set ui.ingress.tls[0].hosts[0]="dashboard.$(BASE_URL)" \
	    --set ui.ingress.tls[0].secretName=ui-tls \
	    --set-string ui.ingress.annotations.cert-manager\\.io/cluster-issuer=$(CLUSTER_ISSUER) \
            --set keycloak.ingress.enabled=true \
            --set keycloak.ingress.hosts[0].host="keycloak.$(BASE_URL)" \
            --set keycloak.ingress.hosts[0].paths[0]="/" \
            --set keycloak.ingress.tls[0].hosts[0]="keycloak.$(BASE_URL)" \
            --set keycloak.ingress.tls[0].secretName=keycloak-tls \
	    --set-string keycloak.ingress.annotations.cert-manager\\.io/cluster-issuer=$(CLUSTER_ISSUER) \
	    --set webhookHandler.ingress.enabled=true \
            --set webhookHandler.ingress.hosts[0].host="webhooks.$(BASE_URL)" \
            --set webhookHandler.ingress.hosts[0].paths[0]="/" \
            --set-string webhookHandler.ingress.annotations.kubernetes\\.io/tls-acme=true \
            --set broker.ingress.enabled=true \
            --set broker.ingress.hosts[0].host="broker.$(BASE_URL)" \
            --set broker.ingress.hosts[0].paths[0]="/" \
	    --set ssh.service.type=LoadBalancer \
	    --set ssh.service.port=2020 \
	    --set sshToken.enabled=false \
	    --set sshToken.serviceMonitor.enabled=false \
	    --set sshToken.service.type=LoadBalancer \
	    --set sshToken.service.ports.sshserver=2223 \
	    --set api.replicaCount=1 \
	    --set authServer.replicaCount=1 \
	    --set ssh.replicaCount=1 \
	    --set logs2notifications.replicaCount=1 \
	    --set actionsHandler.replicaCount=1 \
	    --set ui.replicaCount=1 \
	    --set webhookHandler.replicaCount=1 \
	    --set webhooks2tasks.replicaCount=1 \
	    --set api.resources.requests.cpu=0m \
	    --set apiDB.resources.requests.cpu=0m \
	    --set keycloak.resources.requests.cpu=250m \
	    --set keycloak.resources.requests.memory=0Mi \
	    --set broker.resources.requests.cpu=0m \
	    --set broker.resources.requests.memory=0Mi \
	    --set keycloak.resources.requests.memory=0Mi \
	    --set ssh.resources.requests.cpu=0m \
	    lagoon-core \
	    lagoon/lagoon-core
		

lagoon-remote:
	@echo "Installing Lagoon Remote"
	kubectl create namespace lagoon --dry-run=client -o yaml | kubectl apply -f -
	kubectl -n lagoon apply -f config/remote-nats-cert.yml
	kubectl -n lagoon apply -f config/remote-cert.yml
	kubectl apply -f config/bulk-storage.yml
	helm upgrade \
		--install \
		--wait \
		--create-namespace \
		--namespace lagoon \
		--set dockerHost.registry="registry.$(BASE_URL)" \
		--set global.rabbitMQUsername=lagoon \
                --set "global.rabbitMQPassword=$$($(KUBECTL) -n lagoon-core get secret lagoon-core-broker -o json | jq -r '.data.RABBITMQ_PASSWORD | @base64d')" \
		--set lagoon-build-deploy.enabled=true \
                --set lagoon-build-deploy.lagoonTargetName=cozone \
                --set lagoon-build-deploy.lagoonFeatureFlagForceRWX2RWO=enabled \
                --set lagoon-build-deploy.rabbitMQUsername=lagoon \
		--set lagoon-build-deploy.rabbitMQPassword=$$($(KUBECTL) -n lagoon-core get secret lagoon-core-broker -o json | jq -r '.data.RABBITMQ_PASSWORD | @base64d') \
                --set lagoon-build-deploy.rabbitMQHostname=lagoon-core-broker.lagoon-core.svc:5672 \
                --set lagoon-build-deploy.lagoonTargetName=cozone \
                --set lagoon-build-deploy.sshPortalHost=lagoon-remote-ssh-portal.lagoon.svc \
                --set lagoon-build-deploy.sshPortalPort=22 \
                --set lagoon-build-deploy.lagoonTokenHost=lagoon-core-token.lagoon-core.svc \
                --set lagoon-build-deploy.lagoonTokenPort=2223 \
                --set lagoon-build-deploy.lagoonAPIHost=http://lagoon-core-api.lagoon-core.svc:80 \
		--set lagoon-build-deploy.extraArgs[0]="--skip-tls-verify=true" \
                --set lagoon-build-deploy.harbor.enabled=false \
		--set lagoon-build-deploy.unauthenticatedRegistry=registry.$$($(KUBECTL) -n ingress-nginx get services ingress-nginx-controller -o jsonpath='{.status.loadBalancer.ingress[0].ip}').nip.io \
		lagoon-remote \
		lagoon/lagoon-remote

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
		curl -sSL https://github.com/mike-engel/jwt-cli/releases/download/6.2.0/jwt-linux-musl.tar.gz | tar -xzC $$TMPDIR; \
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
		sudo curl -L "https://github.com/uselagoon/lagoon-cli/releases/download/v0.32.1/lagoon-cli-v0.32.1-linux-amd64" \
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
	curl -s -X POST http://api.$(BASE_URL)/graphql \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "$$(jq -n --arg query "$$QUERY" --argjson variables "$$VARIABLES" '{query: $$query, variables: $$variables}')";
	echo "Assigning user as platform owner"; \
		QUERY='mutation ($$user: UserInput!, $$role: PlatformRole!) { addPlatformRoleToUser(user: $$user, role: $$role) { id email platformRoles } }'; \
		VARIABLES='{ "user": { "email": "jwrf@example.com" }, "role": "OWNER" }'; \
	curl -s -X POST http://api.$(BASE_URL)/graphql \
		-H "Content-Type: application/json" \
		-H "Authorization: Bearer $$TOKEN" \
		-d "$$(jq -n --arg query "$$QUERY" --argjson variables "$$VARIABLES" '{query: $$query, variables: $$variables}')";
	@echo "Adding SSH Key to user"
	SSH_KEY_NAME="jwrf"
	SSH_KEY_VALUE=$$(cat /home/jwrf/.ssh/id_ed25519.pub)
	USER_EMAIL="jwrf@example.com"
	JSON=$$(printf '{"query":"mutation { addUserSSHPublicKey(input: {name: \\"%s\\", publicKey: \\"%s\\", user: {email: \\"%s\\"}}) { id } }"}' "$$SSH_KEY_NAME" "$$SSH_KEY_VALUE" "$$USER_EMAIL")
	curl -s -X POST http://api.$(BASE_URL)/graphql \
	  -H 'Content-Type: application/json' \
	  -H "Authorization: Bearer $$TOKEN" \
	  -d "$$JSON"
	@echo "Getting Keycloak token"
	KEYCLOAK_URL=https://keycloak.$(BASE_URL)
	KEYCLOAK_SECRET=$$(kubectl -n lagoon-core get secret lagoon-core-keycloak -o jsonpath='{.data.KEYCLOAK_ADMIN_API_CLIENT_SECRET}' | base64 --decode)
	echo "Using secret: $$KEYCLOAK_SECRET"
	echo "To URL: $${KEYCLOAK_URL}/auth/realms/master/protocol/openid-connect/token"
	KEYCLOAK_RESPONSE=$$(curl -s -k -X POST "$${KEYCLOAK_URL}/auth/realms/master/protocol/openid-connect/token" \
	  -d "grant_type=client_credentials" \
	  -d "client_id=admin-api" \
	  -d "client_secret=$$KEYCLOAK_SECRET")
	echo "Raw Keycloak response: $$KEYCLOAK_RESPONSE"
	KEYCLOAK_TOKEN=$$(echo "$$KEYCLOAK_RESPONSE" | jq -r '.access_token')
	echo "Obtained token: $$KEYCLOAK_TOKEN"
	INITIAL_USER_EMAIL=jwrf@example.com
	INITIAL_USER_PASSWORD="abcqq"
	@echo "Looking up user ID for email: $$INITIAL_USER_EMAIL"
	export USER_JSON=$$(curl -s -k -H "Authorization: Bearer $$KEYCLOAK_TOKEN" \
		-H "Content-Type: application/json" \
		"$${KEYCLOAK_URL}/auth/admin/realms/lagoon/users?email=$${INITIAL_USER_EMAIL}"); \
	export USER_ID=$$(echo $$USER_JSON | jq -r '.[0].id'); \
	if [ -z "$$USER_ID" ]; then \
		echo "User not found"; \
		exit 1; \
	fi; \
	echo "Resetting password for user ID $$USER_ID"; \
	curl -s -k -X PUT \
		-H "Authorization: Bearer $$KEYCLOAK_TOKEN" \
		-H "Content-Type: application/json" \
		-d '{"type": "password", "value": "'"$$INITIAL_USER_PASSWORD"'", "temporary": false}' \
		"$${KEYCLOAK_URL}/auth/admin/realms/lagoon/users/$$USER_ID/reset-password"
	@echo "Adding cluster to Lagoon"
	lagoon config add \
		--force \
		--graphql http://api.$(BASE_URL)/graphql \
		--ui http://dashboard.$(BASE_URL) \
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
	    --router-pattern='$${environment}-$${project}.app.$(BASE_URL)'
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
nuke:
	@echo "Nuking EVERYTHING"
	bash /usr/local/bin/k3s-uninstall.sh

