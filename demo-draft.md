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

- email: `spring-cloud-services@pivotal.io`
- `staging` -> It's important to verify your configuration is working before using the prod server because there is rate limit on the prod server. A bit of a back story here - I actually bought the domain `animalrescue.online` for this talk, hoping to pretend as a real rescue center, but then we hit the limit last week when we were developing this talk. So let's do it the safe way so we don't run out of quota for this new domain.
- `privateKeySecretRef`: `letsencrypt-staging`. This private key is used to store the ACME/Let's Encrypt account private key, not the private key used for any Certificate resources. The account private key identifies your company/you as a user of the ACME service, and is used to sign all requests/communication with the ACME server to validate your identity.
- `HTTP01` challenge: `HTTP01` is easy to automate to issue certificates for a domain that points to your web servers. ACME server will give the client a token and expect to find it at a certain path on your domain. And because if how it works, it doesn’t allow issueing wildcard certificates.
- `DNS-01` challenge: you can issue certificates containing wildcard domain names with this, as long as you can provide a service account that can mange your domain.

#### Add DNS record for ingress

To save some time in this demo, I have created the DNS record ahead of time for the hostnames specified in my ingress, so that we can use http challenge to quickly get our cert.

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

In a environment where you don't have a single entry point to all your services and can't just add a wildcard DNS record for all your domains, you probably wants to get this step more automated and integrated in your deployment. Yes automating DNS mapping will slow down the HTTP Challenge process because DNS records takes time to propagate, but the benefit of automation may outweight the delay depends on the use cases. And if you are already using DNS challenge then you have nothing to lose!

Let's take a detour to see how to do automate it, then we will come back to TLS.

Just like how KubeDNS adds internal DNS records to make services reachable internally, there is a tool called [ExternalDNS](https://github.com/kubernetes-sigs/external-dns) that configures your DNS providers accordingly. It retrieves a list of resources from the Kubernetes API to determine a desired list of DNS records, and configures your DNS providers accordingly.

We will install it with helm chart, but to configure it to use our DNS provider, we need to configure it.

Helm value:

```yaml
# Sources specify the types of kubernetes resources we are watching for. In our example, we only expose services through ingress, so we can remove `service` from our sources.
sources:
  - service
  - ingress

# Domain filters tells external DNS to filter on your hosted DNS zones with matching domain.
# Omitting this setting allows you to process all available hosted zones.
domainFilters:
  - kubedemo.xyz

provider: google

google:
  project: cf-spring-scs

  # We need to specify a service account because our cluster is on Tanzu Kubernetes Grid but our DNS is on GCP. You can skip this setting if your cluster is with the same cloud provider as your DNS server. However, it's still recommended to have a separate DNS management account dedicated for DNS management.
  serviceAccountSecret: cloud-dns-admin

  # External DNS uses `credentials.json` as key by default to retrieve the service account info from the secret. Since I had to give this file a more descriptive name, I need to also set the secret key here.
  serviceAccountSecretKey: gcp-dns-account-credentials.json

# `sync` will sync up the whole zone and remove unknown domains. It is a great option if you are 100% sure that the external-dns would be the only manager of the zone. It handles the removal of the DNS records if the corresponding k8s resources are removed. Since I'm sharing this zone with Ollie, I'll use upsert-only so I don't ruin his plan.
policy: upsert-only
```

We promised external-dns a service account that has access to manage DNS, so let's add a secretGenerator to our kustomization yaml that generates this secret using my account key file on my machine.

Add to `k8s/kustomization.yaml`

```yaml
secretGenerator:
- name: cloud-dns-admin
  type: Opaque
  namespace: external-dns
  files:
  - secret/gcp-dns-account-credentials.json

  # This credentials file was pulled down with gcloud CLI earlier and it's not checked in to Git. If you are trying out our repo after this talk, you will not be able to use this directly. Also, your cloud provider may need different configuration so check out external-dns doc for more information.
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

Wait until it's running

```bash
watch -n 1 kubectl get all -n external-dns
```

Start watching dns and logs

```bash
watch -n 1 gcloud dns record-sets list --zone kubedemo-zone --filter=name~'.*bella.*'
stern external -n external-dns
```

In Ingress yaml, duplicate a route and change the domain. See the record shows up.

#### Enable TLS

Now, back to TLS. Since we have valid DNS records for the urls, we should be able to handle the HTTP challenge from let's encrypt.
So, let's encrypt!

Add the Let's Encrypt yaml file in `k8s/kustomization.yaml`

Now add the following annotation to ingress to use cert-manager:

```yaml
annotations:
  # In addition to existing annotations
  cert-manager.io/cluster-issuer: "letsencrypt-staging"
  kubernetes.io/tls-acme: "true"

  # cert-manager.io/cluster-issuer: "letsencrypt-staging" # We are telling our ingress to use the let's encrypt staging issuer
  # kubernetes.io/tls-acme: "true" # Remember the endpoint that let's encrypt uses to verify the token? This annotation tells ingress to exclude that path from authentication.
spec:
  # <Add description here, also talk about when would you want separete certs> <Let's encrypt allow up to 100 domains per cert>
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
kubectl describe ingress
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

### With Autocert

[Doc](https://github.com/smallstep/autocert)

1. Install Autocert

With Helm:

```bash
helm install autocert smallstep/autocert --namespace autocert --create-namespace
```

The output from installation is helpful here.

First of all, it tells us to label the namespace where we want to enable autocert. Let's add that to the yaml in our project so it get's version controlled.

```yaml
metadata:
  labels:
    autocert.step.sm: enabled
```

The second command teaches us how to check which namespaces have autocert enabled:

```bash
kubectl get namespace -L autocert.step.sm
```

The next three commands are important if we want to generate a certificate for external uses, for example calling a k8s app from TAS. We won't cover this case today, but at least I want to run this last command and show you the internal CA has been created.

1. Now let's annotate the our node app deployment to trigger autocert

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

The certs are created now. But do we get mTLS? Not yet. If we come back to this diagram, the last step still requires our manual work.

Just to show the before stage before we update the app, let's curl the service without a cert to see how it responds:

```bash
functions netshoot # To show what it is
netshoot
curl https://partner-adoption-center.animal-rescue.svc.cluster.local
curl https://partner-adoption-center
```

It's time to transform our node app!

1. Use the cert in the node app
git compare with `k8s-mTLS` branch and explain the differences.

1. Update service to be on port 443

1. Deploy a mtls client

Add `curl-mtls-client.yaml` to `external-api/k8s/kustomization.yaml`.
This is a simple image that uses the certs injected by autocert and periodically makes request to this URL we specified here.

Verify it works in the logs

```bash
stern curl-mtls-client
```

Just to uncover the last bit of secret here, let's get into the container and make this curl request by hand.

```bash
set CURL_MTLS_CLIENT (kubectl get pods -l app=curl-mtls-client -o jsonpath='{$.items[0].metadata.name}')
k exec -it $CURL_MTLS_CLIENT -- curl https://partner-adoption-center.animal-rescue.svc.cluster.local
k exec -it $CURL_MTLS_CLIENT -- curl https://partner-adoption-center.animal-rescue.svc.cluster.local -k
k exec -it $CURL_MTLS_CLIENT -- curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://partner-adoption-center.animal-rescue.svc.cluster.local
```

[How it works](https://github.com/smallstep/autocert#how-it-works)
