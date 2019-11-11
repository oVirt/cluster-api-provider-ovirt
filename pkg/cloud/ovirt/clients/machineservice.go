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
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	"github.com/pkg/errors"
	"k8s.io/klog"

	ovirtsdk "github.com/ovirt/go-ovirt"

	"github.com/ovirt/cluster-api-provider-ovirt/pkg/ovirtapi"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"

	ovirtconfigv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
)

type InstanceService struct {
	Connection *ovirtsdk.Connection
	ClusterId  string
	TemplateId string
	MachineName string
}

type Instance struct {
	*ovirtsdk.Vm
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

func GetOvirtConnectionConf() (ovirtapi.Connection, error) {

	//// expecting ovirt-config.yaml at ~/.ovirt/ovirt-config.yaml or at env VAR OVIRT_CONFIG
	//file, err := os.Open("~/.ovirt/ovirt-config.yaml")
	//if err != nil {
	//	return ovirtapi.Connection{}, err
	//}
	//in, err := ioutil.ReadAll(file)
	//if err != nil {
	//	return ovirtapi.Connection{}, err
	//}
	//out := ovirtapi.Connection{}
	//
	//err = yaml.Unmarshal(in, &out)
	//if err != nil {
	//	return ovirtapi.Connection{}, err
	//}


	// just for debug
	//klog.Infof("the ovirt config loaded is: %v", out)
	ovirtconf := ovirtapi.Connection{
		Url:      "https://rgolan.usersys.redhat.com:8443/ovirt-engine/api",
		Username: "admin@internal",
		Password: "123",
		CAFile:   "",
	}

	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	certURL, _ := url.Parse(ovirtconf.Url)
	certURL.Path = "ovirt-engine/services/pki-resource"
	certURL.RawQuery = url.PathEscape("resource=ca-certificate&format=X509-PEM-CA")

	resp, err := client.Get(certURL.String())
	if err != nil || resp.StatusCode != http.StatusOK {
		return ovirtconf, fmt.Errorf("error downloading ovirt-engine certificate %s with status %v", err, resp)
	}
	defer resp.Body.Close()

	file, err := os.Create("/tmp/ovirt-engine.ca")
	if err != nil {
		return ovirtconf, fmt.Errorf("failed writing ovirt-engine certificate %s", err)
	}
	io.Copy(file, resp.Body)
	ovirtconf.CAFile = file.Name()
	return ovirtconf, nil
}

func NewInstanceServiceFromMachine(machine *machinev1.Machine) (*InstanceService, error) {
	machineSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}

	//getCredentialsSecret()
	connection, err := GetOvirtConnectionConf()
	if err != nil {
		return nil, err
	}
	service, err := NewInstanceServiceFromConf(connection)
	service.ClusterId = machineSpec.ClusterId
	service.TemplateId = machineSpec.TemplateId
	service.MachineName = machine.Name
	return service, err
}

func NewInstanceService() (*InstanceService, error) {
	return NewInstanceServiceFromConf(ovirtapi.Connection{})
}

func NewInstanceServiceFromConf(connection ovirtapi.Connection) (*InstanceService, error) {

	con, err := ovirtsdk.NewConnectionBuilder().
		URL(connection.Url).
		Username(connection.Username).
		Password(connection.Password).
		CAFile(connection.CAFile).
		Build()

	if err != nil {
		return nil, fmt.Errorf("failed to create ovirt api client: %v", err)
	}

	return &InstanceService{Connection: con}, nil
}

func (is *InstanceService) InstanceCreate(name string, config *ovirtconfigv1.OvirtMachineProviderSpec) (instance *Instance, err error) {
	if config == nil {
		return nil, fmt.Errorf("create Options need be specified to create instace")
	}

	cluster := ovirtsdk.NewClusterBuilder().Id(config.ClusterId).MustBuild()
	template := ovirtsdk.NewTemplateBuilder().Id(config.TemplateId).MustBuild()
	vm, err := ovirtsdk.NewVmBuilder().Name(config.Name).Cluster(cluster).Template(template).Build()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct VM struct")
	}

	klog.Infof("creating VM: %v", vm)
	response, err := is.Connection.SystemService().VmsService().Add().Vm(vm).Send()
	if err != nil {
		klog.Errorf("Failed creating VM", err)
		return nil, err
	}

	return &Instance{response.MustVm()}, nil
}

func (is *InstanceService) InstanceDelete(id string) error {
	klog.Infof("deleting VM with ID: %s", id)
	_, err := is.Connection.SystemService().VmsService().VmService(id).Remove().Send()
	return err
}

func (is *InstanceService) GetInstanceList(opts *InstanceListOpts) ([]*Instance, error) {
	var instanceList []*Instance

	response, err := is.Connection.SystemService().VmsService().List().Send()
	if err != nil {
		klog.Errorf("Failed to fetch list of VMs for the cluster")
		return nil, err
	}

	if vms, exists := response.Vms(); exists {
		// TODO (rgolan) very inefficient get all query.
		//  Need to fetch all by cluster id and by Tag
		// which is set the to openshift cluster Id
		klog.Infof("Search return %s vms", len(vms.Slice()))
		for _, vm := range vms.Slice() {
			if cluster, ok := vm.Cluster(); ok {
				id, _ := cluster.Id()
				if id == is.ClusterId {
					name, _ := vm.Name()
					klog.Infof("Found VM: %v", name)
					instanceList = append(instanceList, &Instance{Vm: vm})
				}
			}
		}
	}
	return instanceList, nil
}

func (is *InstanceService) GetInstance(resourceId string) (instance *Instance, err error) {
	klog.Infof("fetching VM by ID: %s", resourceId)
	if resourceId == "" {
		return nil, fmt.Errorf("ResourceId should be specified to  get detail.")
	}
	response, err := is.Connection.SystemService().VmsService().VmService(resourceId).Get().Send()
	if err != nil {
		return nil, err
	}
	return &Instance{Vm: response.MustVm()}, nil
}
