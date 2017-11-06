# kapprover

_kapprover_ is a tool meant to be deployed in Kubernetes clusters that use the
[TLS client certificate bootstrapping] flow. It will monitor
and automatically approve Certificate Signing Requests
based on the the policy selected at startup.

The easiest way to deploy _kapprover_ is to use the provided `deployment.yaml`
resource.

[TLS client certificate bootstrapping]: https://kubernetes.io/docs/admin/kubelet-tls-bootstrapping/
