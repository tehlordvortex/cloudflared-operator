# cloudflared-operator

Manages cloudflared replicas for an application on Kubernetes,
ensuring replicas are always scheduled on the same nodes as the workloads.

## Deployment

The CRD can be found at [yaml/cfdtunnels.cloudflared-operator.vrtx.sh.yaml](yaml/cfdtunnels.cloudflared-operator.vrtx.sh.yaml).
A sample Kustomize manifest is provided in [yaml/kustomize](yaml/kustomize), which makes the following assumptions:

- The operator will be installed in the `cfd-system` namespace.
- The operator will watch `CfdTunnel`s and `EndpointSlice`s across the cluster.
- The operator will create `DNSEndpoint`s in it's namespace (if using the External DNS integration).

You may also use the [single file bundle](yaml/bundle.yaml).

## Features

- Creates locally managed tunnels using Cloudflare's API
- Deploys and continuously patches a `cloudflared` deployment for each `CfdTunnel`, ensuring there's
always a replica running on the same node.
  - This includes restarting to apply configuration changes.
- Optionally, uses [External DNS](https://kubernetes-sigs.github.io/external-dns/latest/)'s `DNSEndpoint` CRD to configure DNS record(s) for the tunnel.
