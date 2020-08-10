# Certs

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
    --version v0.16.1 \
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

### With Traefik

https://containo.us/traefik/

## Service to service

### Without mTLS

### Add in mTLS

### Linkerd

https://linkerd.io/

### With Autocert

https://github.com/smallstep/autocert
