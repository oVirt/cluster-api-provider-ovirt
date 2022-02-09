# This repository is inactive, please refer to: https://github.com/openshift


# cluster-api-provider-ovirt

[![Docker Repository on Quay](https://quay.io/repository/ovirt/cluster-api-provider-ovirt/status "Docker Repository on Quay")](https://quay.io/repository/ovirt/cluster-api-provider-ovirt)

Implementation of the oVirt provider for the [cluster-api project] version `v1beta` \
using openshift/cluster-api-provider api, which implements the machine actuator.

# Development

Fast development cycle is to build the binaries, `manager` and `machine-controller-manager` \
and run those against a running cluster kubeconfig.

## build
```
make build
```

## run the components locally

```console
$ export KUBECONFIG=path/to/kubecofig

$  bin/manager &

$  bin/machine-controller-manager --namespace openshift-machine-api --metrics-addr=:8888 &
``` 
