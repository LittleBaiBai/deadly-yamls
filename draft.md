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

https://containo.us/traefik/

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

### Linkerd

https://linkerd.io/

### With Autocert

https://github.com/smallstep/autocert
