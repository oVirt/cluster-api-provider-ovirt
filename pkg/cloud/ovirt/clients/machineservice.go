/*
Copyright 2018 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package clients

import (
	"fmt"
	"github.com/ovirt/cluster-api-provider-ovirt/pkg/ovirtapi"
	"gopkg.in/yaml.v2"
	"k8s.io/client-go/kubernetes"

	ovirtconfigv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clusterv1 "sigs.k8s.io/cluster-api/pkg/apis/cluster/v1alpha1"
)

const CloudsSecretKey = "ovirt.conf"

type InstanceService struct {
	ovirtApi ovirtapi.OvirtApi
}

type Instance struct {
	ovirtapi.VM
}

type SshKeyPair struct {
	Name string `json:"name"`

	// PublicKey is the public key from this pair, in OpenSSH format.
	// "ssh-rsa AAAAB3Nz..."
	PublicKey string `json:"public_key"`

	// PrivateKey is the private key from this pair, in PEM format.
	// "-----BEGIN RSA PRIVATE KEY-----\nMIICXA..."
	// It is only present if this KeyPair was just returned from a Create call.
	PrivateKey string `json:"private_key"`
}

type InstanceListOpts struct {
	// Name of the image in URL format.
	Image string `q:"image"`

	// Name of the flavor in URL format.
	Flavor string `q:"flavor"`

	// Name of the server as a string; can be queried with regular expressions.
	// Realize that ?name=bob returns both bob and bobb. If you need to match bob
	// only, you can use a regular expression matching the syntax of the
	// underlying database server implemented for Compute.
	Name string `q:"name"`
}

func GetOvirtConnectionConf(kubeClient kubernetes.Interface, namespace string, secretName string) (ovirtapi.Connection, error) {
	zeroConf := ovirtapi.Connection{}

	if secretName == "" {
		return zeroConf, nil
	}

	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return zeroConf, err
	}

	content, ok := secret.Data[CloudsSecretKey]
	if !ok {
		return zeroConf, fmt.Errorf("oVirt credentials secret %v did not contain key %v",
			secretName, CloudsSecretKey)
	}

	var c = ovirtapi.Connection{}
	err = yaml.Unmarshal(content, &c)
	if err != nil {
		return zeroConf, fmt.Errorf("failed to unmarshal clouds credentials stored in secret %v: %v", secretName, err)
	}

	return c, nil
}

// TODO: Eventually we'll have a NewInstanceServiceFromCluster too
func NewInstanceServiceFromMachine(kubeClient kubernetes.Interface, machine *clusterv1.Machine) (*InstanceService, error) {
	machineSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}
	connection, err := GetOvirtConnectionConf(kubeClient, machine.Namespace, machineSpec.CloudsSecret)
	if err != nil {
		return nil, err
	}
	return NewInstanceServiceFromConf(connection)
}

func NewInstanceService() (*InstanceService, error) {
	return NewInstanceServiceFromConf(ovirtapi.Connection{})
}

func NewInstanceServiceFromConf(connection ovirtapi.Connection) (*InstanceService, error) {

	ovirtApi, err := ovirtapi.NewOvirt(connection)
	if err != nil {
		return nil, fmt.Errorf("failed to create ovirt api client: %v", err)
	}

	return &InstanceService{ovirtApi: ovirtApi}, nil
}

func (is *InstanceService) InstanceCreate(name string, config *ovirtconfigv1.OvirtMachineProviderSpec, cmd string, keyName string) (instance *Instance, err error) {
	if config == nil {
		return nil, fmt.Errorf("create Options need be specified to create instace")
	}
	create, err := is.ovirtApi.Post("vms", ovirtapi.VM{
		Name: name,
		Cluster: ovirtapi.NameId{Name: "Default"},
		Template: ovirtapi.NameId{Name: "Blank"},
	})

	vm, err := is.ovirtApi.GetVMById(create)
	return &Instance{vm}, nil
}

func (is *InstanceService) InstanceDelete(id string) error {
	_, err := is.ovirtApi.Delete(fmt.Sprintf("vms/%s", id))
	return err
}

func (is *InstanceService) GetInstanceList(opts *InstanceListOpts) ([]*Instance, error) {
	var instanceList []*Instance
	vms, err := is.ovirtApi.GetVMs("")
	if err != nil {
		return nil, err
	}
	for _, vm := range vms {
		instanceList = append(instanceList, &Instance{VM: vm})
	}
	return instanceList, nil
}

func (is *InstanceService) GetInstance(resourceId string) (instance *Instance, err error) {
	if resourceId == "" {
		return nil, fmt.Errorf("ResourceId should be specified to  get detail.")
	}
	vm, err := is.ovirtApi.GetVMById(resourceId)
	return &Instance{VM: vm}, err
}
