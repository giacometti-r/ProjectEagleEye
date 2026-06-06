# Kubernetes GitOps

This directory contains the GitOps deployment for `cyber-news-alert`.

## Bootstrap

1. Install Argo CD in the cluster.
2. Configure Argo CD with SOPS/KSOPS support and mount the age private key.
   If the Argo CD application reports `exec: "sh": executable file not found in $PATH`,
   the `ksops` ConfigManagementPlugin is being run in a sidecar image without a shell.
   Configure the CMP generate command without `sh`:

```yaml
apiVersion: argoproj.io/v1alpha1
kind: ConfigManagementPlugin
metadata:
  name: ksops
spec:
  generate:
    command: [kustomize]
    args: [build, --enable-alpha-plugins, --enable-exec, .]
```

   The plugin sidecar must also have `kustomize` and `ksops` in `PATH`, and the
   SOPS age private key must be mounted for the repo-server/plugin container.
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

Render the manifests with KSOPS enabled:

```bash
kubectl kustomize --enable-alpha-plugins --enable-exec k8s/overlays/prod \
  | kubectl apply --dry-run=client -f -
```
