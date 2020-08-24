# Demo draft

## Basic Auth on API

### Without auth

Deploy animal-rescue api and test viewing the page and `/api/animals` endpoint

### Manual secret creation

1. Create secret

    ```bash
    kubectl create secret generic animal-rescue-basic --from-literal=username=alice  --from-literal=password=test
    ```

1. Use the secret in the container, use `basic` profile

    ```bash
    env:
      - name: SPRING_PROFILES_ACTIVE
        value: basic
      - name: ANIMAL_RESCUE_SECURITY_BASIC_PASSWORD
        valueFrom:
          secretKeyRef:
            name: animal-rescue-basic
            key: password
      - name: ANIMAL_RESCUE_SECURITY_BASIC_USERNAME
        valueFrom:
          secretKeyRef:
            name: animal-rescue-basic
            key: username
    ```

1. Deploy and verify basic auth working with the app
1. Show 401 accessing the API
1. Add basic auth configuration to external API deployment

```yaml
          - name: ANIMAL_RESCUE_PASSWORD
            valueFrom:
              secretKeyRef:
                name: animal-rescue-basic
                key: password
          - name: ANIMAL_RESCUE_USERNAME
            valueFrom:
              secretKeyRef:
                name: animal-rescue-basic
                key: username
```

1. Edit server.js to use basic auth from secret

```js
const response = await axios.get(`${animalRescueBaseUrl}/api/animals`, {
    auth: {
        username: animalRescueUsername,
        password: animalRescuePassword
    }
});
```

1. Another API use the same secret to access `/api/animals` endpoint

### ingress + basic auth

To remove the need to restart all the pods or to watch for secrets change, use [ingress](https://kubernetes.github.io/ingress-nginx/examples/auth/basic/)

#### Remove basic auth from the applications

Revert to startdemo tag

#### Install Nginx with Helm

[ingress-nginx doc](https://kubernetes.github.io/ingress-nginx/deploy/)

```bash
helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
kubectl create namespace nginx
helm install ingress-s1p -n nginx ingress-nginx/ingress-nginx
```

It outputs an example ingress. Create an `animal-rescue-ingress.yaml` file with that content, add backend for both apps, and remove the tls part for now. It will look like this:

```yaml
apiVersion: networking.k8s.io/v1beta1
kind: Ingress
metadata:
  annotations:
    kubernetes.io/ingress.class: nginx
  name: animal-rescue-ingress
  namespace: animal-rescue
spec:
  rules:
    - host: spring.animalrescue.online
      http:
        paths:
          - backend:
              serviceName: animal-rescue
              servicePort: 80
    - host: partner.spring.animalrescue.online
      http:
        paths:
          - backend:
              serviceName: partner-adoption-center
              servicePort: 80
```

Run the recommended command from the output to start waiting on external IP.

```bash
kubectl --namespace nginx get services -o wide -w ingress-s1p-ingress-nginx-controller
```

_Note for ourselves: Make sure to run the following command after `helm uninstall`_

```bash
kubectl delete -A ValidatingWebhookConfiguration ingress-s1p-ingress-nginx-admission
```

_Note for ourselves: Because this is deployed on GKE, so I had to run the following commmand to enable webhook._

```bash
kubectl create clusterrolebinding cluster-admin-binding \
  --clusterrole cluster-admin \
  --user $(gcloud config get-value account)
```

#### Create secret

```bash
htpasswd -c auth alice # Password is MD5 encrypted by default
cat auth # Relatively safe to version control it with a private repo?
kubectl create secret generic ingress-basic-auth --from-file=auth
kubectl get secret ingress-basic-auth -o yaml
```

Alternatively, create service with `secretGenerator`:

```yaml
secretGenerator:
- name: ingress-basic-auth
  type: Opaque
  files:
  - auth
```

#### Add basic auth annotation to ingress

```yaml
  annotations:
    # type of authentication
    nginx.ingress.kubernetes.io/auth-type: basic
    # name of the secret that contains the user/password definitions
    nginx.ingress.kubernetes.io/auth-secret: ingress-basic-auth
```

#### Remove all basic auth reference in code

`backend/k8s/deployment.yaml` - Remove env vars including profiles
`external-api/k8s/deployment.yaml` - Remove basic auth envs
`external-api/server.js` - Remove reading basic auth envs and `auth` option when making the request.

#### Create ingress

Update skaffold to include the ingress yaml, add DNS entries for to `/etc/hosts`:

```text
${ingressIP} spring.animalrescue.online
${ingressIP} partner.spring.animalrescue.online
```

#### Talk about services no longer need to be loadbalanced

#### Verify it works

Visit `spring.animalrescue.online` and `partner.spring.animalrescue.online`

#### ingress-nginx plugin

the `krew` plugin manager for `kubectl` can be used to install the `ingress-nginx` plugin. This makes it easier to monitor the ingress

`kubectl krew install ingress-nginx`
`kubectl ingress-nginx ingresses`
`kubectl ingress-nginx backends -n nginx`

#### Secrets limitations

Secrets still have some limitations, in practice a `kubeclt` user will have access to all the secrets in a namespace they have access to.
Kubernetes does have Role Based Access Control (RBAC) however these are not fine-grained enough to grant or deny access to specific secrets
(although you can limit which users have access to *any* secrets in a namespace). Using the below command, we can read the basic authentication MD5 previously
created)

`kubectl get secrets ingress-basic-auth-XXXXX -o json | jq -r '.data.auth' | base64 -d`
`alice:$apr1$nrfZ.qd2$E8x2.pi2q7Aa6ewFZ9XtS1`

The password is still MD5 hashed, offering some protection but more secure environments may want to use an external secret manager to inject
secrets into Pods, such as HashiCorp Vault

## Exposing trustworthy service to the world

### With Ingress + Cert Manager

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

[More info about the chart](https://github.com/helm/charts/tree/master/stable/cert-manager)

_Note for ourselves: steps to uninstall certmanager:_

```bash
helm --namespace cert-manager delete cert-manager
kubectl delete namespace cert-manager
kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v0.16.1/cert-manager.crds.yaml

# If namespace stuck in terminating state
kubectl delete apiservice v1beta1.webhook.cert-manager.io
```

#### Create staging yaml

From the output of Helm install, we know we need to set up a ClusterIssuer to begin issuing certificates.

Click on the hyperlink, quickly show what's possible with certmanager:

- Self signed cert - use this to test webhook

    ```bash
    k apply -f k8s/test-issuer-for-certmanager.yaml
    kubectl describe certificate -n cert-manager-test
    kubectl delete -f k8s/test-issuer-for-certmanager.yaml
    ```

- CA - This issuer type is typically used in a Public Key Infrastructure (PKI) setup to secure your infrastructure components to establish mTLS or otherwise provide a means to issue certificates where you also own the private key.

- ACME - The ACME Issuer type represents a single account registered with the Automated Certificate Management Environment (ACME) Certificate Authority server.

Then go to the ACME section and copy the yaml into `letsencrypt.yaml`

- `staging` -> `prod` in the file. It's normally recommended to verify your configuration is working before using the prod server because there is rate limit on the prod server. But out of blind confidence and for time sake, we will skip that bit in this demo.
- email: `spring-cloud-services@pivotal.io`
- `privateKeySecretRef`: `letsencrypt-prod`. This private key is used to store the ACME/Let's Encrypt account private key, not the private key used for any Certificate resources. The account private key identifies your company/you as a user of the ACME service, and is used to sign all requests/communication with the ACME server to validate your identity.
- `HTTP01` challenge: `HTTP01` is easy to automate to issue certificates for a domain that points to your web servers. ACME server will give the client a token and expect to find it at a certain path on your domain. And because if how it works, it doesn’t allow issueing wildcard certificates.
- `DNS-01` challenge: you can issue certificates containing wildcard domain names with this, as long as you can provide a service account that can mange your domain.
- server: `https://acme-v02.api.letsencrypt.org/directory` (Remove `staging` from the example url).

[Additional information](https://letsencrypt.org/docs/challenge-types/#dns-01-challenge)

#### Add DNS record for ingress

Quickly mention [ExternalDNS](https://github.com/kubernetes-sigs/external-dns)

Then do it manually:

```bash
# List existing records
gcloud dns record-sets list --zone "animal-rescue-zone"

# Get ingress IP
set ingressIp (kubectl get ingress -o json | jq -r .items[0].status.loadBalancer.ingress[0].ip) # Fish syntax, use export in bash

# Add new record
gcloud dns record-sets transaction start --zone="animal-rescue-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="spring.animalrescue.online" \
  --ttl="30" \
  --type="A" \
  --zone="animal-rescue-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="partner.spring.animalrescue.online" \
  --ttl="30" \
  --type="A" \
  --zone="animal-rescue-zone"
gcloud dns record-sets transaction execute --zone="animal-rescue-zone"

# Remove record
gcloud dns record-sets transaction start --zone="animal-rescue-zone"
gcloud dns record-sets transaction remove $ingressIp \
  --name="spring.animalrescue.online" \
  --ttl="30" \
  --type="A" \
  --zone="animal-rescue-zone"
gcloud dns record-sets transaction remove $ingressIp \
  --name="partner.spring.animalrescue.online" \
  --ttl="30" \
  --type="A" \
  --zone="animal-rescue-zone"
gcloud dns record-sets transaction execute --zone="animal-rescue-zone"
```

It takes a few minutes for the DNS record getting propogated.

#### Switch to use the preconfigured ingress

Update the settings so we keep the IP.

#### Enable TLS

Create ClusterIssuer with LetsEncrypt

Add the Let's Encrypt yaml file in `kustomization.yaml`

Now add the following annotation to ingress to use cert-manager:

```yaml
annotations:
  # Additional to existing annotations
  cert-manager.io/cluster-issuer: "letsencrypt-prod"
  kubernetes.io/tls-acme: "true"
spec:
  tls:
    - hosts:
        - spring.animalrescue.online
      secretName: animal-rescue-certs
    - hosts:
        - partner.spring.animalrescue.online
      secretName: partner-certs
```

Wait until certificate is successfully issued:

```bash
kubectl describe ingress echo-ingress
```

Should see:

```bash
Events:
  Type    Reason             Age   From                      Message
  ----    ------             ----  ----                      -------
  Normal  CREATE             97s   nginx-ingress-controller  Ingress default/echo-ingress
  Normal  CreateCertificate  97s   cert-manager              Successfully created Certificate "echo-tls"
```

Verify TLS:

```bash
curl http://spring.animalrescue.online/api/animals # Should get `308 Permanent Redirect` back
curl https://spring.animalrescue.online/api/animals # Should get `401` back
curl https://spring.animalrescue.online/api/animals --user alice:test # Should get `200`response back
```

## OAuth2 integration

### Internal user access - cluster OIDC

Ingress + oauth2-proxy

### External user - external IDP

Dex? Spring Authorization Server? Gateway?

## Service to service

### Manually

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

### With Autocert

[Doc](https://github.com/smallstep/autocert)

1. Make sure the cluster is kubernetes 1.9 or later with admission webhooks enabled

```bash
$ kubectl version --short
Client Version: v1.16.6-beta.0
Server Version: v1.16.12+vmware.1
$ kubectl api-versions | grep "admissionregistration.k8s.io/v1beta1"
admissionregistration.k8s.io/v1beta1
```

1. Install

```bash
kubectl run autocert-init -it --rm --image smallstep/autocert-init --restart Never
```

or with Helm:

```bash
helm repo add smallstep https://smallstep.github.io/helm-charts/
helm install smallstep/autocert
```

Store installation info:

```bash
Store this information somewhere safe:
  CA & admin provisioner password: I6C7f4Iku446iqmPkhsZNMyVdjjnY198
  Autocert password: HMM0seFbhRKwsR38FPXLSfqpXUOTijJM
  CA Fingerprint: e477129c307aaf55024d5b30e03dbe2997c3775016bc7a9091fce6ffac7125e2
```

1. Enable for the namespace

To label the default namespace run:

```bash
kubectl label namespace default autocert.step.sm=enabled
```

To check which namespaces have autocert enabled run:

```bash
$ kubectl get namespace -L autocert.step.sm
NAME          STATUS   AGE   AUTOCERT.STEP.SM
default       Active   59m   enabled
```

1. Deploy a mtls server

```bash
kubectl apply -f hello-mtls.yaml
```

Verify cert is created and injected:

```bash
$ export HELLO_MTLS=$(kubectl get pods -l app=hello-mtls -o jsonpath='{$.items[0].metadata.name}')
$ kubectl exec -it $HELLO_MTLS -c hello-mtls -- ls /var/run/autocert.step.sm
root.crt  site.crt  site.key
$ kubectl exec -it $HELLO_MTLS -c hello-mtls -- cat /var/run/autocert.step.sm/site.crt | step certificate inspect --short -
```

1. Deploy a mtls client

```bash
kubectl apply -f hello-mtls-client.yaml
```

Verify it works in the logs

```bash
stern hello-mtls-client
```

```bash
$ export HELLO_MTLS_CLIENT=$(kubectl get pods -l app=hello-mtls-client -o jsonpath='{$.items[0].metadata.name}')
$ kubectl exec $HELLO_MTLS_CLIENT -c hello-mtls-client -- curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://hello-mtls.default.svc.cluster.local
Hello, hello-mtls-client.default.pod.cluster.local!
```

[How it works](https://github.com/smallstep/autocert#how-it-works)

**Pros:**

- Private keys are kept on container disk only and are never stored in Kubernetes secrets - which may not be encrypted in the storage backend - or transferred over the network
- Easy to set up and run

**Cons:**

- Autocert works really well if the applications already knows how to load certificate and keys, how to periodically reload them, and how to do TLS termination. But this may not be the case most of the times, especially with Java where SSL/TLS can be expensive. In cases like these, it may be beneficial to offload TLS termination to a local proxy.

### With a mesh (TSM?)

## Committing to Spring Boot

### Spring Cloud Binding

### Spring Cloud Kubernetes

## Other products

Maybe a chart compare all of them side by side for features and usabilities?

### TSM

### Istio

### Traefik

[Basic Auth](https://docs.traefik.io/middlewares/basicauth/)

[TLS](https://docs.traefik.io/https/tls/)

[mTLS](https://docs.traefik.io/https/tls/#client-authentication-mtls)

### Linkerd

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
