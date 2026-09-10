# Quickstart Guide

## Prerequisites

- A running Kubernetes cluster (e.g. `kind`, `minikube`, `k3s`, or GKE/EKS)
- `kubectl` configured with cluster-admin access
- Gateway API CRDs and an ingress controller (e.g. Envoy Gateway) if using TLS routing

## Install Custom Resource Definitions (CRDs)

Apply the generated CRDs to your cluster:

```bash
kubectl apply -f crds/generated.yaml
```

This registers:
- `Template` (`cardinal.noctf.dev/v1`): Blueprints defining challenge pods, resource limits, and route specs.
- `Instance` (`cardinal.noctf.dev/v1`): Ephemeral running sandboxes allocated to teams or players.

## Deploying Cardinal

You can deploy Cardinal directly into your cluster using the provided Kubernetes manifest:

```bash
kubectl apply -f examples/00-cardinal-deployment.yaml
```

This sets up:
- Namespaces: `cardinal-system` (for Cardinal) and `challenges` (for player instances)
- RBAC: ServiceAccount, ClusterRole, and Bindings giving Cardinal permissions over its managed resources
- Deployment: The Cardinal controller deployment with leader election support

### Alternatively: Running Locally for Development

You can run Cardinal directly against your active kubeconfig context:

```bash
cargo run --bin cardinal -- --config examples/config.example.yaml
```

If `--config` is omitted, Cardinal automatically attempts to load `/etc/cardinal/config.yaml` or falls back to built-in defaults. See [`examples/config.example.yaml`](examples/config.example.yaml) for a full example of all configuration settings.

## Deploying Your First Challenge

### Example 1: Web Challenge (HTTP/TLS via Gateway API)

Apply [`examples/01-web-challenge.yaml`](examples/01-web-challenge.yaml):

```bash
kubectl apply -f examples/01-web-challenge.yaml
```

Cardinal will automatically:
- Create a `ReplicaSet` running the `whoami` pod.
- Create a headless `Service` (`clusterIP: None`) for internal traffic.
- Generate dual `NetworkPolicy` objects (`team1-whoami-int` and `team1-whoami-ext`) isolating the instance.
- Create a Gateway API `TLSRoute` exposing `whoami-<hash>.c.example.com`.
- Publish the live endpoint in `instance.status.resources.endpoints`.

Check status:

```bash
kubectl get cinst -n challenges -o wide
```

### Example 2: Pwn Challenge (Raw TCP with Dynamic Port Allocation)

Apply [`examples/02-tcp-pwn-challenge.yaml`](examples/02-tcp-pwn-challenge.yaml):

```bash
kubectl apply -f examples/02-tcp-pwn-challenge.yaml
```

Setting `port: 0` instructs Cardinal to dynamically allocate a free port from `--auto-ports`. The allocated port is recorded on the instance status.

### Example 3: Multi-Pod Challenge with Internal Service Linking

Apply [`examples/03-multi-service-challenge.yaml`](examples/03-multi-service-challenge.yaml):

```bash
kubectl apply -f examples/03-multi-service-challenge.yaml
```

Pods can communicate securely using templated service discovery:
- `{{ services.<pod_name> }}` automatically resolves to the sibling pod's headless service (`clusterIP: None`, named `<instance>-svc-<pod_name>`).

### Example 4: Automatic Expiration (TTL / Ephemeral Sandbox)

Apply [`examples/04-instance-with-ttl.yaml`](examples/04-instance-with-ttl.yaml):

```bash
kubectl apply -f examples/04-instance-with-ttl.yaml
```

By annotating the instance with `cardinal.noctf.dev/expiresAt` (an RFC3339 timestamp), Cardinal automatically schedules an expiration check. Once the timestamp passes, Cardinal deletes the `Instance`, triggering cascading deletion of all child pods, services, and routes.

## Instance Lifecycle & Upgrades

Instances are **immutable snapshots** pinned to the template version at creation time. Updating a `Template` does not auto-roll running instances, preventing active player sessions or shared challenge state from being wiped accidentally.

To apply template changes to running instances:

1. **Recreate the instance (standard player flow):**
   ```bash
   kubectl delete cinst <instance-name> -n challenges
   kubectl apply -f <instance-manifest>.yaml
   ```

2. **Trigger a rolling restart (preserves routes and allocated ports):**
   ```bash
   kubectl annotate cinst <instance-name> -n challenges \
     cardinal.noctf.dev/restartedAt="$(date -u +%Y-%m-%dT%H:%M:%SZ)" --overwrite
   ```

3. **Emergency global upgrade (forces all active instances to roll up):**
   ```bash
   kubectl annotate ctmpl <template-name> -n challenges \
     cardinal.noctf.dev/minTemplateGeneration="9999" --overwrite
   ```
   Cardinal automatically caps this annotation to the template's current generation so future template edits do not trigger unwanted rolls.

## Cleaning Up

Delete instances manually when done:

```bash
kubectl delete cinst -n challenges team1-whoami team1-echo team1-multi team1-ephemeral-session
```

Kubernetes `ownerReferences` automatically cascades and deletes all owned ReplicaSets, Services, NetworkPolicies, and TLSRoutes instantly.
