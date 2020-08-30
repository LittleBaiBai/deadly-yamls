# Demo draft

## Basic Auth on API

### Without auth

Generate k8s resources using code completion

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

1. Show `BasicAuthenticationSecurityConfiguration` and explain how env var gets mapped from `ANIMAL_RESCUE_SECURITY_BASIC` to `animal.rescue.security.basic`
1. Explain that the `basic` profile is activated using an env var in the deployment and that the profile is used to include the `BasicAuthenticationSecurityConfiguration`
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
1. Change the secret and rolling restart

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
    - host: animalrescue.kubedemo.xyz
      http:
        paths:
          - backend:
              serviceName: animal-rescue
              servicePort: 80
    - host: partner.kubedemo.xyz
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

generatorOptions:
  disableNameSuffixHash: true
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
${ingressIP} animalrescue.kubedemo.xyz
${ingressIP} partner.kubedemo.xyz
```

#### Talk about services no longer need to be loadbalanced

#### Verify it works

Visit `animalrescue.kubedemo.xyz` and `partner.kubedemo.xyz`

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
helm repo add jetstack https://charts.jetstack.io
helm repo update
helm install cert-manager jetstack/cert-manager \
    --create-namespace \
    --namespace cert-manager \
    --version v0.16.1 \
    --set installCRDs=true
```

[More info about the chart](https://github.com/helm/charts/tree/master/stable/cert-manager)

#### Skip this during demo

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

- `staging` -> It's important to verify your configuration is working before using the prod server because there is rate limit on the prod server. A bit of a back story here - I actually bought the domain `animalrescue.online` for this talk, hoping to pretend as a real rescue center, but then we hit the limit last week when we were developing this talk. So let's do it the safe way so we don't run out of quota for this new domain.
- email: `spring-cloud-services@pivotal.io`
- `privateKeySecretRef`: `letsencrypt-staging`. This private key is used to store the ACME/Let's Encrypt account private key, not the private key used for any Certificate resources. The account private key identifies your company/you as a user of the ACME service, and is used to sign all requests/communication with the ACME server to validate your identity.
- `HTTP01` challenge: `HTTP01` is easy to automate to issue certificates for a domain that points to your web servers. ACME server will give the client a token and expect to find it at a certain path on your domain. And because if how it works, it doesn’t allow issueing wildcard certificates.
- `DNS-01` challenge: you can issue certificates containing wildcard domain names with this, as long as you can provide a service account that can mange your domain.

#### Add DNS record for ingress

Because how HTTP challange works, we will need a valid DNS entry available for let's encrypt server to verify the token. So let's focus on that next.

A new DNS entry takes a few minutes to get propagated, so I have created DNS entries that matches the domain name we specified in ingress ahead of time.

```bash
# List existing records
gcloud dns record-sets list --zone kubedemo-zone --filter=name~'.*bella.*'
```

#### Skip this section in resentation

```bash
# Get ingress IP
set ingressIp (kubectl get ingress -o json | jq -r .items[0].status.loadBalancer.ingress[0].ip) # Fish syntax, use export in bash

# Add new record
gcloud dns record-sets transaction start --zone="kubedemo-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="animalrescue.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="partner.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction execute --zone="kubedemo-zone"

# Remove record
gcloud dns record-sets transaction start --zone="kubedemo-zone"
gcloud dns record-sets transaction remove $ingressIp \
  --name="animalrescue.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction remove $ingressIp \
  --name="partner.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction execute --zone="kubedemo-zone"
```

#### Demo External DNS for ingress

Adding or removing DNS records from Google Cloud DNS is relatively easy with the `gcloud` plugin, and most of the cloud DNS providers offers API for ease of automation.

In a non demo environment, you probably wants to get this step more automated and integrated in your deployment.

It would be great if DNS records can get automatically generated for the new domains specified in kubernetes, and optionally, get deleted on resource removal. Right?

Well, what if I tell you there is a way!

Just like how KubeDNS makes services discoverable internally, [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) retrieves a list of resources from the Kubernetes API to determine a desired list of DNS records, and configures your DNS providers accordingly.

To install it with helm chart, we need to configure it.

Helm value:

```yaml
# Sources specify the types of kubernetes resources we are watching for. In our example, we only expose services through ingress, so we can remove `service` from our sources.
sources:
  - service
  - ingress

# This looks like domain filters but it's actually filtering on a zones with matching domains.
# and omitting this setting allows you to process all available hosted zones.
domainFilters:
  - kubedemo.xyz

provider: google

google:
  project: cf-spring-scs

  # We need to specify a service account because my cluster is on PKS but my DNS is on GKE. If you. You can skip this setting if your cluster is with the same cloud provider as your DNS server. However, it's still recommended to have a separate DNS management account dedicated for DNS management.
  serviceAccountSecret: cloud-dns-admin

  # External DNS will use `credentials.json` by default to retrieve the service account info. Since I had to give this file a more descriptive name, I need to also set the secret key here.
  serviceAccountSecretKey: gcp-dns-account-credentials.json

policy: upsert-only # This is the default value. `sync` will sync up the whole zone and remove unknown domains. `sync` is a great option if you are 100% sure that the external-dns would be the only manager of the zone. I initially wanted to show you how it automatically removes DNS record when I remove the ingress rule, but then I wiped out all the DNS records needed by Ollie. So A) you will have to imagine this `sync` demo in your head, and B), be careful with this option.
```

We promised external-dns a service account that has access to manage DNS, so let's add that to our kustomization yaml.

Add to `k8s/kustomization.yaml`

```yaml
secretGenerator:
- name: cloud-dns-admin
  type: Opaque
  namespace: external-dns
  files:
  - secret/gcp-dns-account-credentials.json

generatorOptions:
  disableNameSuffixHash: true
```

Let's install it with helm chart.

```yaml
  helm:
    flags:
      install: [ "--create-namespace" ]
    releases:
      - name: external-dns
        chartPath: bitnami/external-dns
        valuesFiles: [k8s/external-dns-helm-values.yaml]
        remote: true
        namespace: external-dns
```

Start watching dns and logs

```bash
watch gcloud dns record-sets list --zone kubedemo-zone --filter=name~'.*bella.*'
stern external -n external-dns
```

In Ingress yaml, duplicate a route and change the domain. See the record shows up.
Remove that route and record goes away.

#### Enable TLS

Now, with valid DNS records, we should be able to handle the HTTP challenge from let's encrypt.
So, let's encrypt!

Add the Let's Encrypt yaml file in `k8s/kustomization.yaml`

Now add the following annotation to ingress to use cert-manager:

```yaml
annotations:
  # In addition to existing annotations
  cert-manager.io/cluster-issuer: "letsencrypt-staging"
  kubernetes.io/tls-acme: "true"
spec:
  tls:
    - hosts:
        - animalrescue.bella.kubedemo.xyz
      secretName: animal-rescue-certs
    - hosts:
        - partner.bella.kubedemo.xyz
      secretName: partner-certs
```

Wait until certificate is successfully issued:

```bash
kubectl describe ingress animal-rescue-ingress
```

Should see:

```bash
Events:
  Type    Reason             Age   From                      Message
  ----    ------             ----  ----                      -------
  Normal  CREATE             97s   nginx-ingress-controller  Ingress default/echo-ingress
  Normal  CreateCertificate  97s   cert-manager              Successfully created Certificate "echo-tls"
```

Check certificate status:

```bash
k get certificates
```

Verify TLS:

```bash
curl http://animalrescue.bella.kubedemo.xyz/api/animals # Should get `308 Permanent Redirect` back
curl https://animalrescue.bella.kubedemo.xyz/api/animals # Should get `401` back
curl https://animalrescue.bella.kubedemo.xyz/api/animals --user alice:test # Should get `200`response back
```

After we verified that everything works fine, we shall switch to use prod server.

- Duplicate `letsencrypt-staging.yaml`
- Change all `staing` to `prod`
- Remove `staging-` from `server`
- Update to `letsencypt-prod.yaml` to `k8s/kustomization.yaml`
- Use the prod issuer in ingress

Visit the site again to see a trusted cert!

## OAuth2 integration

### Internal user access - cluster OIDC
!!PROBABLY GOING TO SCRATCH THIS. LEAVING HERE FOR NOW TO REUSE SOME OF THE WORDING!!

For internal facing applications, there is often a need to authenticate access to APIs using internal identity systems.
Kubernetes can integrate the cluster security with an external identity provider using the Open ID Connect protocol (OIDC).
OIDC is an extension of the OAuth2 specification that provides some new authorization flows on top of the existing OAuth2 auth flows.
Our applications can also use the clusters auth service as an authorization service. This should only be done for internal
systems as it is not a good idea to store external user identities in the cluster.

In this demo we are using Tanzu Kubernetes Grid integrated (TKGi) which uses UAA auth service. UAA was originally built
for Cloud Foundry, it is a complete solution for user authentication and authorization. If you are using a different cluster,
the process of authorization will similar as it uses the OIDC specification, however the steps for creating users will be different.

We are going to use an `authorization_code` flow to protect access to our webpage. This flow will redirect users to a username / password
form to enter their credentials, and then allow access to the original page.


#### Create client and user
```shell script
uaa create-client animal-rescue \
  --display_name AnimalRescueAuth \
  --authorities "uaa.resource" \
  --authorized_grant_types "authorization_code,refresh_token" \
  --scope "resource.read,resource.write,openid,profile,email" \
  --redirect_uri http://animalrescue.kubedemo.xyz \
  -s springone2020
```
The client will be used by our backend API server by Spring Security to authorize user access to the animal rescue web process.
Typically, a client is created for each API. It is possible to authenticate to our API just using the client, however it is
considered best practice to create user accounts for each person that needs access to the API and only use the client in the API
to validate the users access.

### External user - external IDP

Ingress Nginx can be configured to provide a simple Single Sign On (SSO) for applications by forwarding authentication
requests to an external service.

We will install a simple OAuth2 proxy in the cluster that uses GitHub as a backend for authorization
TODO: Update links to HTTPS

#### Register a new application in GitHub
1. Login to GitHub and go to settings | Developer Settings | New OAuth App
1. Enter Animal Rescue for name, http://animalrescue.kubedemo.xyz for homepage
 and http://auth.kubedemo.xyz/oauth2/callback for callback url
1. Take a note of client ID and secret

#### Deploy oauth2-proxy
1. Generate random base64 string to be used for cookie secret
 `python -c 'import os,base64; print(base64.urlsafe_b64encode(os.urandom(16)).decode())'`
1. Create secrets for oauth2_proxy client_id, client_secret from GitHub app registration and the cookie secret
```shell script
    export COOKIE_SECRET=...
    export GITHUB_CLIENT_ID=...
    export GITHUB_CLIENT_SECRET=...
    kubectl -n animal-rescue create secret generic oauth2-proxy-creds \
    --from-literal=cookie-secret=${COOKIE_SECRET} \
    --from-literal=client-id=${GITHUB_CLIENT_ID} \
    --from-literal=client-secret=${GITHUB_CLIENT_SECRET}
```
Helm will be used to install `oauth2-proxy` as it provides a simple mechanism to override settings. These custom settings
are stored in a file

`cat oauth2-proxy-helm-values.yaml`

With helm, we can also set these values individually using the `--set key=value` flag

Helm will configure a deployment for oauth2-proxy and also an ingress. This is needed in order to configure TLS for the service using cert-manager.
The TLS configuration process is the same as we did with the other 2 microservices earlier

```shell script
helm install oauth2-proxy stable/oauth2-proxy --values oauth2-proxy-helm-values.yaml
```

Watching the status of the pod will let us know when it is ready
```shell script
k get pod -l app=oauth2-proxy --watch
```
As before, we will need to create a DNS record for the auth service using the ingress IP

```shell script
export ingressIp =$(kubectl get ingress -o json | jq -r ".items[0].status.loadBalancer.ingress[0].ip")
gcloud dns record-sets transaction start --zone="kubedemo-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="auth.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction add $ingressIp \
  --name="partner.kubedemo.xyz" \
  --ttl="30" \
  --type="A" \
  --zone="kubedemo-zone"
gcloud dns record-sets transaction execute --zone="kubedemo-zone"
```

## Service to service

### Manually

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
helm install autocert smallstep/autocert --namespace autocert --create-namespace
```

Store installation info:

```bash
Store this information somewhere safe:
  CA & admin provisioner password: I6C7f4Iku446iqmPkhsZNMyVdjjnY198
  Autocert password: HMM0seFbhRKwsR38FPXLSfqpXUOTijJM
  CA Fingerprint: e477129c307aaf55024d5b30e03dbe2997c3775016bc7a9091fce6ffac7125e2
```

1. Enable for the namespace

Add label the `animal-rescue` namespace yaml:

```yaml
metadata:
  labels:
    autocert.step.sm: enabled
```

That's equivalent to running the following command:

```bash
kubectl label namespace animal-rescue autocert.step.sm=enabled
```

To check which namespaces have autocert enabled run:

```bash
kubectl get namespace -L autocert.step.sm
```

1. Annotate external-api deployment

```yaml
spec:
  template:
    metadata:
      annotations:
        autocert.step.sm/name: partner-adoption-center.animal-rescue.svc.cluster.local
```

1. Describe the pod to see a sidecar is created

Verify cert is created and injected:

```bash
set PARTNER_POD (kubectl get pods -l app=partner-adoption-center -o jsonpath='{$.items[0].metadata.name}')
kubectl exec -it $PARTNER_POD -c partner-adoption-center -- ls /var/run/autocert.step.sm
# Should see root.crt  site.crt  site.key
kubectl exec -it $PARTNER_POD -c partner-adoption-center -- cat /var/run/autocert.step.sm/site.crt | step certificate inspect --short -
# Should see subject being set and validity to be 1 day
```

1. Use the cert in the node app

```js
const https = require('https');
const tls = require('tls');
const fs = require('fs');
const axios = require('axios');

const animalRescueBaseUrl = process.env.ANIMAL_RESCUE_BASE_URL;
const animalRescueUsername = process.env.ANIMAL_RESCUE_USERNAME || '';
const animalRescuePassword = process.env.ANIMAL_RESCUE_PASSWORD || '';

const requestAnimalsFromAnimalRescue = async () => {
    try {
        const response = await axios.get(`${animalRescueBaseUrl}/api/animals`);
        return { animals: response.data };
    } catch (e) {
        console.error(e);
        return { error: e };
    }
};

const config = {
    ca: '/var/run/autocert.step.sm/root.crt',
    key: '/var/run/autocert.step.sm/site.key',
    cert: '/var/run/autocert.step.sm/site.crt',
    ciphers: 'ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-ECDSA-AES128-GCM-SHA256',
    minVersion: 'TLSv1.2',
    maxVersion: 'TLSv1.2'
};

const createSecureContext = () => {
    return tls.createSecureContext({
        ca: fs.readFileSync(config.ca),
        key: fs.readFileSync(config.key),
        cert: fs.readFileSync(config.cert),
        ciphers: config.ciphers,
    });
};

let ctx = createSecureContext();

fs.watch(config.cert, (event, filename) => {
    if (event === 'change') {
        ctx = createSecureContext();
    }
});

const serverOptions = {
    requestCert: true,
    rejectUnauthorized: true,
    SNICallback: (servername, cb) => {
        cb(null, ctx);
    }
};

const server = https.createServer(serverOptions, async (req, res) => {
    if (req.url === '/') {
        res.writeHead(200, {'Content-Type': 'text/html'});

        const {animals, error} = await requestAnimalsFromAnimalRescue();
        console.log(animals, error);
        if(error) {
            res.write(`<html><body><p>Failed to retrieve animals: ${error}</body></html>`);
        } else {
            const animalHtmlList = animals.map(animal => `<li>${animal.name}</li>`).join('');
            res.write(`<html><body><p>Animals available at Animal Rescue: ${animalHtmlList}</body></html>`);
        }

        res.end();
    }
});

server.listen(5000);
console.info('Partner Adoption Center web server is running on port 5000..');
```

Do a git diff and talk about the differences.

1. Update service to be on port 443

1. Deploy a mtls client

Add `curl-mtls-client.yaml` to `external-api/k8s/kustomization.yaml`

Verify it works in the logs

```bash
stern curl-mtls-client
```

```bash
set CURL_MTLS_CLIENT (kubectl get pods -l app=curl-mtls-client -o jsonpath='{$.items[0].metadata.name}')
k exec -it $CURL_MTLS_CLIENT -- bash
curl https://partner-adoption-center.animal-rescue.svc.cluster.local
curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://partner-adoption-center
curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://partner-adoption-center.animal-rescue.svc.cluster.local
```

[How it works](https://github.com/smallstep/autocert#how-it-works)
