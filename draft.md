# Certs

## Service to service

### Without mTLS

### Add in mTLS

### With Autocert

## Exposing trustworthy service to the world

### With Ingress + Cert Manager

#### Install Nginx with Helm

https://kubernetes.github.io/ingress-nginx/deploy/

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install my-release ingress-nginx/ingress-nginx
```

#### Deploy an app

kubectl apply -f echo1.yaml
kubectl apply -f echo2.yaml
kubectl apply -f echo-ingress.yaml

At this point the ingress should be configured correctly. Verify with:

```bash
curl spring.animalrescue.online/echo1 // Should get 'echo1'
curl spring.animalrescue.online/echo2 // Should get 'echo2'
```

#### Install CertManager with Helm

```bash
kubectl create namespace cert-manager
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
    --namespace cert-manager \
    --version v0.15.2 \
    --set installCRDs=true
```

Now verify webhook works find:

```bash
kubectl apply -f test-resources.yaml
kubectl describe certificate -n cert-manager-test
kubectl delete -f test-resources.yaml
```

More info about the chart: https://github.com/helm/charts/tree/master/stable/cert-manager

#### Enable TLS

Create ClusterIssuer with LetsEncrypt

```bash
kubectl apply -f letsencrypt-staging.yaml
```

Now configure ingress to perform TLS

```bash
kubectl apply -f echo-ingress-tls.yaml
```

Validate that we are getting a self-signed cert. Then we are ready to move onto prod and create a proper cert for the app.

```bash
kubectl apply -f letsencrypt-prod.yaml
```

Update `echo-ingress-tls.yaml` to use the prod server

```bash
kubectl apply -f echo-ingress-tls.yaml
```

#### Without an ingress controller

With an ingress controller, we can route all requests through it so only one A record was needed with the DNS server. If we want to expose each service directly, it would be helpful to automate the whole thing with [external-dns](https://github.com/kubernetes-sigs/external-dns).

Setting up DNS zone on google cloud


```bash
gcloud dns managed-zones create "animal-rescue-zone" \
    --dns-name "spring.animalrescue.online." \
    --description "Automatically managed zone by kubernetes.io/external-dns"
gcloud dns record-sets list --zone "animal-rescue-zone"
```

### With Traefik

