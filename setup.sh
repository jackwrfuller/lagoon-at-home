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
helm repo update

# Install MetalLB
echo "Installing MetalLB"
helm upgrade --install --create-namespace --namespace metallb-system --wait metallb metallb/metallb
kubectl apply -f config/metallb.yml

echo "Installing Cert Manager"
helm upgrade --install --create-namespace -n cert-manager --wait cert-manager jetstack/cert-manager -f values/cert-manager.yml
kubectl -n lagoon-core apply -f config/lagoon-issuer.yml

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

















