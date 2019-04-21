# Kubernetes cluster-api-provider-ovirt Project

https://github.com/oVirt/cluster-api-provider-ovirt

# UNDER HEAVY DEVELOPMENT

Implementation of the  oVirt provider for the [cluster-api project](https://github.com/kubernetes-sigs/cluster-api).


## Community, discussion, contribution, and support

Learn how to engage with the Kubernetes community on the [community page](http://kubernetes.io/community/).

You can reach the maintainers of this project at:

- [#cluster-api on Kubernetes Slack](http://kubernetes.slack.com/messages/cluster-api)
- [SIG-Cluster-Lifecycle Mailing List](https://groups.google.com/forum/#!forum/kubernetes-sig-cluster-lifecycle)/

### Code of conduct

Participation in the Kubernetes community is governed by the [Kubernetes Code of Conduct](code-of-conduct.md).

## Getting Started

### Prerequisites

1. Install `kubectl` (see [here](http://kubernetes.io/docs/user-guide/prereqs/)).
2. Install [minikube](https://kubernetes.io/docs/tasks/tools/install-minikube/), version 0.30.0 or greater.
3. Install a [driver](https://github.com/kubernetes/minikube/blob/master/docs/drivers.md) for minikube. For Linux, we recommend kvm2. For MacOS, we recommend VirtualBox.
4. An appropriately configured [Go development environment](https://golang.org/doc/install)
5. Build the `clusterctl` tool



### Cluster Creation


```bash
./clusterctl create cluster --help
```



### Interacting with your cluster

Once you have created a cluster, you can interact with the cluster and machine
resources using kubectl:

```bash
kubectl --kubeconfig=kubeconfig get clusters
kubectl --kubeconfig=kubeconfig get machines
kubectl --kubeconfig=kubeconfig get machines -o yaml
```

### Cluster Deletion

1. Delete all of the node Machines in the cluster. Make sure to wait for the
  corresponding Nodes to be deleted before moving onto the next step. After this
  step, the master node will be the only remaining node.

   ```bash
   kubectl --kubeconfig=kubeconfig delete machines -l set=node
   kubectl --kubeconfig=kubeconfig get nodes
   ```

2. Delete the master machine.
    ```bash
    kubectl --kubeconfig=kubeconfig delete machines -l set=master
    ```

3. Delete the ssh keypair that were created for your cluster machine.

   ```bash
   rm -rf $HOME/.ssh/ovirt_tmp*
   ```
