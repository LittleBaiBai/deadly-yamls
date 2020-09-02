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
# helm repo add jetstack https://charts.jetstack.io
# helm repo update
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

(Click on the hyperlink, quickly show what's possible with certmanager)

- CA - allows yout to issue certificates where you own the private key. So CA issuer can be used to set up mTLS

- ACME - The ACME Issuer is what we are looking for because that's what Let's Encrypt uses. Here we can find a sample acme issuer that we can use as a starting point.

Then go to the ACME section and copy the yaml into `letsencrypt.yaml`

- ClusterIssuer: we are using ClusterIssuer here so the issuer would be available cluster-wise. You can also set it to Issuer so it will be scoped to the namespace.
- email: `spring-cloud-services@pivotal.io`
- `staging` -> It's important to verify the configuration is working before switching over to the prod server because the prod server has a rate limit. But for the sake of time, let's do prod directly.
- `privateKeySecretRef`: `letsencrypt`. This secret will be generated by cert manager. We are just giving it a name here, and it will contain the private key to represent us with the ACME server.
- `HTTP01` challenge: This is defining the flow of cert issueing. Let's talk about how that works.

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

#### Enable TLS

Now, back to TLS. Let's encrypt!

(Add the Let's Encrypt yaml file in `k8s/kustomization.yaml`)

And we need to update our ingress to use the issuer

```yaml
annotations:
  # In addition to existing annotations
  cert-manager.io/cluster-issuer: "letsencrypt"
  kubernetes.io/tls-acme: "true"

  # cert-manager.io/cluster-issuer: "letsencrypt-staging" # We are telling our ingress to use the let's encrypt staging issuer
  # kubernetes.io/tls-acme: "true" # This annotation tells ingress to exclude that acme challenge path from authentication.

# Finally we need to enforece TLS for our hosts.
spec:
  tls:
    - hosts:
        - animalrescue.bella.kubedemo.xyz
      secretName: animal-rescue-certs
    - hosts:
        - partner.bella.kubedemo.xyz
      secretName: partner-certs
```

(Wait until certificate is successfully issued)

```bash
kubectl describe ingress animal-rescue-ingress
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

#### Demo External DNS for ingress

In this demo I manually created the DNS records ahead of time. If you have a DNS admin account, then you can automate adding DNS record as part of the deployments. An important thing to note here is that DNS records takes time to propagate, so creating DNS records on the fly will slow down the HTTP Challenge process. But depending on your business need, the benefit of automation may outweight the delay. So let's quickly see how to do this.

We will install a tool called ExternalDNS with helm chart. We need to provide addition values this time, to configure it with our DNS provider. So I have this values file version controled in the repo.

```yaml
# Sources specify the types of kubernetes resources we are watching for. In our example, we only expose services through ingress, so we can remove `service` from our sources.
sources:
  - service
  - ingress

# Domain filters tells external DNS to filter on your hosted DNS zones with matching domain.
domainFilters:
  - kubedemo.xyz

provider: google

google:
  project: cf-spring-scs

  # Service account secret is what external dns uses to manage our DNS zone. Let's add a secret generator to create the secret.
  serviceAccountSecret: cloud-dns-admin

  # When creating a secret with a file, the filename becomes the key and the content of the file becomes the value. This tells external-dns where to retrieve the value.
  serviceAccountSecretKey: gcp-dns-account-credentials.json

# The sync option is great if you are 100% sure that the external-dns would be the only manager of the zone. It handles the removal of the DNS records if the corresponding k8s resources are removed. Since I'm sharing this zone with Ollie, I'll use upsert-only so I don't ruin his plan.
policy: upsert-only
```

We promised external-dns a service account secret, so let's add that with secretGenerator.

Add to `k8s/kustomization.yaml`

```yaml
secretGenerator:
- name: cloud-dns-admin
  type: Opaque
  namespace: external-dns
  files:
  - secret/gcp-dns-account-credentials.json

  # This credentials file was pulled down with gcloud CLI earlier and it's not checked in to Git. So don't expect to see it if you check out our code.
```

Now we are ready to install, since the helm value is in the code base, let's use skaffold to install the helm chart.

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

While we are waiting for skaffold to install everything, let's starting watching our DNS zone:

```bash
watch -n 1 gcloud dns record-sets list --zone kubedemo-zone --filter=name~'.*bella.*'
```

Let's see if external dns is ready:

```bash
watch -n 1 kubectl get all -n external-dns
```

(In Ingress yaml, duplicate a route and change the domain. See the record shows up.)

Start watching dns and logs

```bash
stern external -n external-dns
```

The record will take a few minute travelling to let's encrypt, but we no longer need to manually add DNS entries for enabling TLS.

(Back to slides)

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

First thing first, let's install Autocert With Helm:

```bash
helm install autocert smallstep/autocert --namespace autocert --create-namespace
```

The output from installation is helpful here.

First of all, it tells us to label the namespace where we want to enable autocert. Let's add that to the animal-rescue namespace in our project so it get's version controlled.

```yaml
metadata:
  # Copy the thing below
  labels:
    autocert.step.sm: enabled
```

1. Let's annotate our node app to trigger autocert magic

```bash
kgp -w
```

```yaml
spec:
  template:
    metadata:
      # Copy the thing below
      annotations:
        autocert.step.sm/name: partner-adoption-center.animal-rescue.svc.cluster.local
```

What happens now is that Autocert will deploy a sidecar next to our node app and share a temporary directory for cert files. The sidecar uses a one-time token to generate an initial cert, then for renewal it would simply use mTLS. Once the cert is generated in the sidecar container, then it becomes available to the node app.

```bash
k describe pod partner
```

We can see that there is a volume called cert that's mounted on both containers.

(Highlight the path)

If we take a look inside the container now listing mounted path, we should be seeing the cert files generated by autocert.

```bash
set PARTNER_POD (kubectl get pods -l app=partner-adoption-center -o jsonpath='{$.items[0].metadata.name}')
kubectl exec -it $PARTNER_POD -c partner-adoption-center -- ls /var/run/autocert.step.sm
# Should see root.crt  site.crt  site.key
kubectl exec -it $PARTNER_POD -c partner-adoption-center -- cat /var/run/autocert.step.sm/site.crt | step certificate inspect --short -
# We can see the subject is what we set in the annotation, and the cert is valid for a day. Then the sidecar will take care of the renewal
```

The certs are created now. But to get mTLS fully wired up, we need to update our node app.

It's time to transform our node app!

1. Use the cert in the node app
(git compare with `k8s-mTLS` branch and explain the differences.)

1. Update service to be on port 443

1. Deploy a mtls client

(Add `curl-mtls-client.yaml` to `external-api/k8s/kustomization.yaml`.)
This is a simple image that uses the certs injected by autocert and periodically makes request to this URL we specified here.

Verify it works in the logs

```bash
stern curl-mtls-client
```

Just to uncover the last bit of secret here, let's get into the container and make this curl request by hand.

```bash
set MTLS_CLIENT (kubectl get pods -l app=curl-mtls-client -o jsonpath='{$.items[0].metadata.name}')
# Let's make the same request that the curl-mtls-client is making with all the certs
k exec -it $MTLS_CLIENT -- curl -sS \
       --cacert /var/run/autocert.step.sm/root.crt \
       --cert /var/run/autocert.step.sm/site.crt \
       --key /var/run/autocert.step.sm/site.key \
       https://partner-adoption-center.animal-rescue.svc.cluster.local
# We got the same successful response back
# And now let's make the request without using the generated cert file
k exec -it $MTLS_CLIENT -- curl https://partner-adoption-center.animal-rescue.svc.cluster.local
# We got the response saying failed to verify the server's certificate. This is because the server cert is not a publicly trusted so the curl client is cowardly terminated.
# Let's be bold and tell it to skip server cert validation
k exec -it $MTLS_CLIENT -- curl https://partner-adoption-center.animal-rescue.svc.cluster.local -k
# We are getting a different handshake error. This time it was the server who terminated the request because we didn't provide a cert.
```

[How it works](https://github.com/smallstep/autocert#how-it-works)
