package cluster

import (
	"context"
	"fmt"

	"github.com/gophercloud/gophercloud"
	"github.com/gophercloud/gophercloud/openstack"
	"github.com/gophercloud/utils/openstack/clientconfig"
	providerv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
	providerv1ovirt "github.com/ovirt/cluster-api-provider-ovirt/pkg/cloud/ovirt"
	"github.com/ovirt/cluster-api-provider-ovirt/pkg/cloud/ovirt/clients"
	"github.com/pkg/errors"
	"k8s.io/klog"
	clusterv1 "github.com/openshift/cluster-api/pkg/apis/cluster/v1alpha1"
)

// Actuator controls cluster related infrastructure.
type Actuator struct {
	params providerv1ovirt.ActuatorParams
}

// NewActuator creates a new Actuator
func NewActuator(params providerv1ovirt.ActuatorParams) (*Actuator, error) {
	res := &Actuator{params: params}
	return res, nil
}

// Reconcile creates or applies updates to the cluster.
func (a *Actuator) Reconcile(cluster *clusterv1.Cluster) error {
	klog.Infof("Reconciling cluster %v.", cluster.Name)

	client, err := a.getNetworkClient(cluster)
	if err != nil {
		return err
	}
	networkService, err := clients.NewNetworkService(client)
	if err != nil {
		return err
	}

	// Load provider config.
	desired, err := providerv1.ClusterSpecFromProviderSpec(cluster.Spec.ProviderSpec)
	if err != nil {
		return errors.Errorf("failed to load cluster provider spec: %v", err)
	}

	// Load provider status.
	status, err := providerv1.ClusterStatusFromProviderStatus(cluster.Status.ProviderStatus)
	if err != nil {
		return errors.Errorf("failed to load cluster provider status: %v", err)
	}

	err = networkService.Reconcile(fmt.Sprintf("%s/%s", cluster.ObjectMeta.Namespace, cluster.Name), *desired, status)
	if err != nil {
		return errors.Errorf("failed to reconcile network: %v", err)
	}

	defer func() {
		if err := a.storeClusterStatus(cluster, status); err != nil {
			klog.Errorf("failed to store provider status for cluster %q in namespace %q: %v", cluster.Name, cluster.Namespace, err)
		}
	}()
	return nil
}

// Delete deletes a cluster and is invoked by the Cluster Controller
func (a *Actuator) Delete(cluster *clusterv1.Cluster) error {
	klog.Infof("Deleting cluster %v.", cluster.Name)

	client, err := a.getNetworkClient(cluster)
	if err != nil {
		return err
	}
	_, err = clients.NewNetworkService(client)
	if err != nil {
		return err
	}

	// Load provider config.
	_, err = providerv1.ClusterSpecFromProviderSpec(cluster.Spec.ProviderSpec)
	if err != nil {
		return errors.Errorf("failed to load cluster provider config: %v", err)
	}

	// Load provider status.
	_, err = providerv1.ClusterStatusFromProviderStatus(cluster.Status.ProviderStatus)
	if err != nil {
		return errors.Errorf("failed to load cluster provider status: %v", err)
	}

	// Delete other things

	return nil
}

func (a *Actuator) storeClusterStatus(cluster *clusterv1.Cluster, status *providerv1.OvirtClusterProviderStatus) error {
	ext, err := providerv1.EncodeClusterStatus(status)
	if err != nil {
		return fmt.Errorf("failed to update cluster status for cluster %q in namespace %q: %v", cluster.Name, cluster.Namespace, err)
	}
	cluster.Status.ProviderStatus = ext

	statusClient := a.params.Client.Status()
	if err := statusClient.Update(context.Background(), cluster); err != nil {
		return fmt.Errorf("failed to update cluster status for cluster %q in namespace %q: %v", cluster.Name, cluster.Namespace, err)
	}

	return nil
}

// getNetworkClient returns an gophercloud.ServiceClient provided by openstack.NewNetworkV2
// TODO(chrigl) currently ignoring cluster, but in the future we might store OS-Credentials
// as secrets referenced by the cluster.
// See https://github.com/kubernetes-sigs/cluster-api-provider-openstack/pull/136
func (a *Actuator) getNetworkClient(cluster *clusterv1.Cluster) (*gophercloud.ServiceClient, error) {
	clientOpts := new(clientconfig.ClientOpts)
	opts, err := clientconfig.AuthOptions(clientOpts)
	if err != nil {
		return nil, err
	}

	provider, err := openstack.AuthenticatedClient(*opts)
	if err != nil {
		return nil, fmt.Errorf("create providerClient err: %v", err)
	}

	client, err := openstack.NewNetworkV2(provider, gophercloud.EndpointOpts{
		Region: clientOpts.RegionName,
	})
	if err != nil {
		return nil, err
	}

	return client, nil
}
