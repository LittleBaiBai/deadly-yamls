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


### Manually (Skip this in demo)

Earlier when we looked at cert manager page, we quickly mentioned the CA issuer type
It's possible to reuse what we have set up with Let's Encrypt before. But for mTLS, it's better to use a private CA to avoid exposing your system to all.

It's not trivial to get it to work, and then you will need to worry about cert rotations. So not recommend.

#### Without mTLS

Use the same echo service:

```bash
k apply -f echo1.yaml
```

#### Generate certs

```bash
cd certs
# Need to enable v3 ca generation on mac: https://github.com/jetstack/cert-manager/issues/279
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.crt -extensions v3_ca -config openssl-with-ca.cnf -subj '/CN=Animal Cert Authority'

# Generate the Server Key, and Certificate and Sign with the CA Certificate
openssl req -new -newkey rsa:4096 -keyout server.key -out server.csr -nodes -subj '/CN=animalrescue.online'
openssl x509 -req -sha256 -days 365 -in server.csr -CA ca.crt -CAkey ca.key -set_serial 01 -out server.crt
# Generate the Client Key, and Certificate and Sign with the CA Certificate
openssl req -new -newkey rsa:4096 -keyout client.key -out client.csr -nodes -subj '/CN=another-rescue.org'
openssl x509 -req -sha256 -days 365 -in client.csr -CA ca.crt -CAkey ca.key -set_serial 02 -out client.crt
```

#### Add in mTLS

[Cert Manager doc for adding CA](https://cert-manager.io/docs/configuration/ca/)

[Guide](https://medium.com/@awkwardferny/configuring-certificate-based-mutual-authentication-with-kubernetes-ingress-nginx-20e7e38fdfca)

```bash
# Create secret in Kubernetes cluster
kubectl create secret generic ca-key-pair --from-file=tls.crt=ca.crt --from-file=tls.key=ca.key

# Create CA issuer
k apply -f private-ca-issuer.yaml

# Verify issuer creation
kubectl get issuers private-ca-issuer -o wide
```

Verify:

```bash
curl http://animalrescue.online/echo1 # Should get `400 Forbidden` back
curl https://animalrescue.online/echo1 # Should get `400 Forbidden` back
curl https://animalrescue.online/echo1 --cert ./certs/client.crt --key ./certs/client.key -k # Should get `200` back
```

The certificate request stayed as `in progress` after a very long time, and I'm getting `403` no matter how I make the request. This is not going to work.

## Linkerd

[doc](https://linkerd.io/)

1. Install CLI

```bash
brew install linkerd
linkerd version
linkerd check --pre
```

1. Install linkerd control plane

```bash
linkerd install | kubectl apply -f -
linkerd check # This command waits for installatiion to finish
linkerd -n linkerd top deploy/linkerd-web # view what's been installed
```

1. Deploy demo app

```bash
curl -sL https://run.linkerd.io/emojivoto.yml | kubectl apply -f -
kubectl -n emojivoto port-forward svc/web-svc 8080:80
```

1. Inject linkerd

```bash
kubectl get -n emojivoto deploy -o yaml \
  | linkerd inject - \
  | kubectl apply -f -
```

This command retrieves all of the deployments running in the emojivoto namespace, runs the manifest through linkerd inject, and then reapplies it to the cluster. The linkerd inject command adds annotations to the pod spec instructing Linkerd to add (“inject”) the proxy as a container to the pod spec.

1. Verify

```bash
linkerd -n emojivoto check --proxy
```

**Pros:**

- Automatic mTLS
- CLI to simplify annotations

**Cons:**

- Maybe too feature rich? (Built in Grafana and dashboard)
- Doesn't enforce mTLS

### Without an ingress controller

#### ExternalDNS

With an ingress controller, we can route all requests through it so only one A record was needed with the DNS server. If we want to expose each service directly, it would be helpful to automate the whole thing with [ExternalDNS](https://github.com/kubernetes-sigs/external-dns).

Following [guide with GKE](https://github.com/kubernetes-sigs/external-dns/blob/master/docs/tutorials/gke.md)

https://github.com/paulczar/platform-operations-on-kubernetes/blob/master/docs/gcp-uaa-openid/install.md

1. Setting up DNS zone on google cloud (Skip this in the demo):

```bash
gcloud dns managed-zones create "animal-rescue-zone" \
    --dns-name "spring.animalrescue.online." \
    --description "Automatically managed zone by kubernetes.io/external-dns"
```

Tell the parent zone where to find the DNS records for this zone by adding the corresponding NS records there.

1. See records in the DNS zone:

```bash
gcloud dns record-sets list --zone "animal-rescue-zone"
```

1. Create service account and add secret

Skip this step if the cluster is in the with the same provider of the DNS. Following [this doc](https://knative.dev/docs/serving/using-external-dns-on-gcp/#set-up-externaldns)

```bash
# # Name of the service account you want to create.
export CLOUD_DNS_SA=cloud-dns-admin
export PROJECT_NAME=cf-spring-scs

# Create a new service account for Cloud DNS admin role.
gcloud --project $PROJECT_NAME iam service-accounts \
    create $CLOUD_DNS_SA \
    --display-name "Service Account to support ACME DNS-01 challenge."

# Fully-qualified service account name also has project-id information.
export CLOUD_DNS_SA=$CLOUD_DNS_SA@$PROJECT_NAME.iam.gserviceaccount.com

# Bind the role dns.admin to the newly created service account.
gcloud projects add-iam-policy-binding $PROJECT_NAME \
    --member serviceAccount:$CLOUD_DNS_SA \
    --role roles/dns.admin
gcloud projects add-iam-policy-binding $PROJECT_NAME \
    --member serviceAccount:$CLOUD_DNS_SA \
    --role roles/storage.admin
gcloud projects add-iam-policy-binding $PROJECT_NAME \
    --member serviceAccount:$CLOUD_DNS_SA \
    --role roles/editor

# Download the secret key file for your service account.
gcloud iam service-accounts keys create ~/credentials.json \
    --iam-account=$CLOUD_DNS_SA

# Upload the service account credential to your cluster. This command uses the secret name cloud-dns-key, but you can choose a different name.
kubectl create secret generic cloud-dns-key \
    --from-file=credentials.json=$HOME/credentials.json

# Delete the local secret
rm ~/credentials.json
```

1. Deploy ExternalDNS

[Helm install](https://github.com/bitnami/charts/tree/master/bitnami/external-dns)

[Example helm values](https://github.com/paulczar/platform-operations-on-kubernetes/blob/master/charts/externaldns/helmfile/base.yaml.gotmpl)

```bash
helm repo add bitnami https://charts.bitnami.com/bitnami
helm install external-dns bitnami/external-dns
```

With Helm value:

```yaml
sources:
  - service
  - ingress

domainFilters:
  - spring.animalrescue.online

provider: google

google:
  project: cf-spring-scs
  serviceAccountSecret: cloud-dns-key
```

1. Update the service to be `LoadBalancer` with the `external-dns.alpha.kubernetes.io/hostname` annotation

```bash
kubectl apply -f echo1.yaml
kubectl apply -f echo2.yaml
```

1. PKS-DNS

https://code.vmware.com/samples/6164/pks-dns---Automated-DNS-creation-for-PKS-clusters#:~:text=What%20Is%20This%3F,to%20access%20their%20cluster%20externally.
https://neonmirrors.net/post/2019-08/pks-dns/

#### Manage TLS

https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/

1. Microsoft Open service mesh

https://techcrunch.com/2020/08/05/microsoft-launches-open-service-mesh/

1. AWS TLS support

https://kubernetes.io/docs/concepts/services-networking/service/#ssl-support-on-aws

1. step

https://github.com/smallstep/cli#installing

1. Manual mTLS

https://medium.com/@awkwardferny/configuring-certificate-based-mutual-authentication-with-kubernetes-ingress-nginx-20e7e38fdfca

1. Contour with CertManager

https://projectcontour.io/guides/cert-manager/

1. Digitalocean

https://www.digitalocean.com/community/tutorials/how-to-set-up-an-nginx-ingress-with-cert-manager-on-digitalocean-kubernetes

1. gcloud set up firewall rule for linkerd

https://linkerd.io/2/reference/cluster-configuration/#private-clusters

1. Istio with wildcard certificates

https://github.com/stefanprodan/istio-gke/blob/master/docs/istio/05-letsencrypt-setup.md

1. mTLS with spring boot

https://medium.com/@niral22/2-way-ssl-with-spring-boot-microservices-2c97c974e83