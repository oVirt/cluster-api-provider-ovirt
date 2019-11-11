package clients

import (
	"context"
	"fmt"
	apicorev1 "k8s.io/api/core/v1"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
)

func getCredentialsSecret(coreClient client.Client, machine machinev1.Machine, spec v1alpha1.OvirtMachineProviderSpec) (map[string][]byte, error) {
	if spec.CredentialsSecret == nil {
		return nil, nil
	}
	var credentialsSecret apicorev1.Secret

	if err := coreClient.Get(context.Background(), client.ObjectKey{Namespace: machine.GetNamespace(), Name: spec.CredentialsSecret.Name}, &credentialsSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("error getting credentials secret %q in namespace %q: %v", spec.CredentialsSecret.Name, machine.GetNamespace(), err)
		}
	}

	return credentialsSecret.Data, nil
}

