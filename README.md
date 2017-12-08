# kapprover

_kapprover_ is a tool meant to be deployed in Kubernetes clusters that use the
[TLS client certificate bootstrapping] flow. It will monitor
and automatically approve Certificate Signing Requests
based on the the policy specified in the command-line arguments.

The easiest way to deploy _kapprover_ is to use the provided `deployment.yaml`
resource. This implements a reasonable default policy for POD TLS server/client
certificates.

## Approval policies

The approval policy is specified on the command line as three sets of
_inspectors_. An inspector performs a policy check on a certificate request
and either takes no action, letting the request go on to the next inspector,
or indicates adverse action should be taken, returning a message as to why.

What adverse action is taken depends on which of the three sets the inspector
is in. They are, in order of application to requests:

* filters: The request is ignored. Presumably some other approver will process
it.
* deniers: The request is denied.
* warners: The message is logged at warning level, but the request is still
approved. This is intended to allow graceful transition to stricter
policies.

If a request passes all of the configured filters and deniers it is then
approved.

## Request cleanup

Once a request is approved or denied, kapprover will delete it after an
amount of time that is specified on the command line.

## Custom inspectors

To use a custom inspector, fork (only) the main package and have it import
the necessary inspectors.

[TLS client certificate bootstrapping]: https://kubernetes.io/docs/admin/kubelet-tls-bootstrapping/
