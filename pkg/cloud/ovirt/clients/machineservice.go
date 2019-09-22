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
	"strconv"

	"k8s.io/client-go/kubernetes"

	"github.com/ovirt/cluster-api-provider-ovirt/pkg/ovirtapi"

	//clusterv1 "github.com/openshift/cluster-api/pkg/apis/cluster/v1alpha1"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	ovirtconfigv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
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
	Name string `json:"name"`
}

func GetOvirtConnectionConf(kubeClient kubernetes.Interface, namespace string, secretName string) (ovirtapi.Connection, error) {

	secret, err := kubeClient.CoreV1().Secrets(namespace).Get(secretName, metav1.GetOptions{})
	if err != nil {
		return ovirtapi.Connection{}, err
	}

	url, _ := secret.StringData["engine_url"]
	username, _ := secret.StringData["engine_username"]
	password, _ := secret.StringData["engine_password"]
	insecure, _ := strconv.ParseBool(secret.StringData["engine_insecure"])
	cafile, _ := secret.StringData["engine_insecure"]

	ovirtconf := ovirtapi.Connection{
		Url:      url,
		Username: username,
		Password: password,
		Insecure: insecure,
		CAFile:   cafile,
	}

	return ovirtconf, nil
}

func NewInstanceServiceFromMachine(kubeClient kubernetes.Interface, machine *machinev1.Machine) (*InstanceService, error) {
	machineSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}
	connection, err := GetOvirtConnectionConf(kubeClient, machine.Namespace, machineSpec.CredentialsSecret.Name)
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

func (is *InstanceService) InstanceCreate(name string, config *ovirtconfigv1.OvirtMachineProviderSpec) (instance *Instance, err error) {
	if config == nil {
		return nil, fmt.Errorf("create Options need be specified to create instace")
	}
	create, err := is.ovirtApi.Post("vms", ovirtapi.VM{
		Name: config.Name,
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
