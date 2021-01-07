# Multi Registry Proxy

This is a fork of the `Serverless Container Registry Proxy`. Other than the original project it is a
forwarding proxy that lets you pull container images from Docker Hub or other registries. If you want to
pull from multiple registries, your container runtime needs to add a namespace query parameter to the
request as specified in opencontainers/distribution-spec#66. Support for this has already been implemented
in `containerd` version 1.4 (see containerd/containerd#4413).

Since most registries swap out the actual container images to some object store (e.g. S3). the proxy
server is following redirects by itself. This simplifies the configuration of access rules a lot.

## Containerd configuration

To forward all requests through the proxy. You can apply the following settings to your `containerd.toml`:

```
[plugins.cri.registry.mirrors]
  [plugins.cri.registry.mirrors."docker.io"]
    endpoint = ["https://registry-1.docker.io"]
  [plugins.cri.registry.mirrors."*"]
    endpoint = ["https://HostIP:Port"]
```

## Building

Download the source code, and build as a container image:

    docker build --tag gcr.io/[YOUR_PROJECT]/gcr-proxy .

Then, push to a registry like:

    docker push gcr.io/[YOUR_PROJECT]/gcr-proxy

## Configuration

### Environment variables

- `DEFAULT_REGISTRY`: (defaults to `https://registry-1.docker.io`)

## TODO

- `ALLOW_REGISTRIES`
- `REGISTRY_AUTH`
- `CACHE_MEM`
- `CACHE_DIR`