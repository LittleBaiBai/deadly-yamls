# Play with certs

## Kind

### Following this guide on setting up ingress on Kind

https://kind.sigs.k8s.io/docs/user/ingress/

```bash
kind create cluster --config=kind-config-ingress.yaml
kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/kind/deploy.yaml
kubectl wait --namespace ingress-nginx \
  --for=condition=ready pod \
  --selector=app.kubernetes.io/component=controller \
  --timeout=90s
kubectl apply -f echo1.yaml
kubectl apply -f echo2.yaml
kubectl apply -f echo-ingress.yaml
```

At this point the ingress should be configured correctly. Verify with:

```bash
curl localhost/echo1 // Should get 'echo1'
curl localhost/echo2 // Should get 'echo2'
```

### TLS

Install CertManager

```bash
kubectl apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.15.2/cert-manager.yaml
```

Create ClusterIssuer with LetsEncrypt

```bash
kubectl apply -f letsencrypt-staging.yaml
```

Now configure ingress to perform TLS

```bash
kubectl apply -f echo-ingress-tls.yaml
```

Need to add a local domain name

```bash
sudo -- sh -c "echo $(minikube ip)  meow.com >> /etc/hosts"
```

### Current state:

```bash
Status:
  Conditions:
    Last Transition Time:  2020-08-06T18:44:19Z
    Message:               Waiting for CertificateRequest "echo-tls-2180926147" to complete
    Reason:                InProgress
    Status:                False
    Type:                  Ready
```

## PKS

### Install Nginx with Helm

https://kubernetes.github.io/ingress-nginx/deploy/

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
helm install my-release ingress-nginx/ingress-nginx
```

### Install CertManager with Helm

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

## Manual

https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/


Additional links:
https://itnext.io/automated-tls-with-cert-manager-and-letsencrypt-for-kubernetes-7daaa5e0cae4


## mTLS

https://medium.com/@awkwardferny/configuring-certificate-based-mutual-authentication-with-kubernetes-ingress-nginx-20e7e38fdfca

## Interesting tools I found along the way
https://github.com/smallstep/cli#installing

