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
      - name: SPRING_PROFIELS_ACTIVE
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

1. Another API use the same secret to access `/api/animals` endpoint

### Generated secret

### ingress + basic auth

https://kubernetes.github.io/ingress-nginx/examples/auth/basic/

### Traefik

https://docs.traefik.io/middlewares/basicauth/

## Exposing trustworthy service to the world

### With Ingress + Cert Manager

#### Install Nginx with Helm

[ingress-nginx doc](https://kubernetes.github.io/ingress-nginx/deploy/)

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

[More info about the chart](https://github.com/helm/charts/tree/master/stable/cert-manager)

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
curl http://animalrescue.online/echo1 # Should get `308 Permanent Redirect` back
curl https://animalrescue.online/echo1 # SHould get `echo1` back
```

### With Traefik

[Doc](https://containo.us/traefik/)

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
