# Kubernetes GitOps

This directory contains the GitOps deployment for `cyber-news-alert`.

## Bootstrap

1. Install Argo CD in the cluster.
2. Configure Argo CD with SOPS/KSOPS support and mount the age private key.
3. Replace `.sops.yaml` with your age public key.
4. Replace the placeholder values in `k8s/overlays/prod/secrets.enc.yaml`.
5. Encrypt the secret manifest:

```bash
sops --encrypt --in-place k8s/overlays/prod/secrets.enc.yaml
```

6. Commit the encrypted secret and apply the Argo CD application:

```bash
kubectl apply -f k8s/argocd/application.yaml
```

Argo CD syncs `k8s/overlays/prod`, creates the `cyber-news-alert` namespace,
runs PostgreSQL in that namespace, and schedules the hourly monitor CronJob.

## Local manifest check

Before the secret is encrypted, you can render the manifests with:

```bash
kubectl apply --dry-run=client -k k8s/overlays/prod
```
