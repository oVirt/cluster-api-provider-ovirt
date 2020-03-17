/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"crypto/tls"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/openshift/cluster-api/pkg/util"
	"github.com/pkg/errors"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog"

	ovirtsdk "github.com/ovirt/go-ovirt"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"

	ovirtconfigv1 "github.com/openshift/cluster-api-provider-ovirt/pkg/apis/ovirtprovider/v1beta1"
)

type InstanceService struct {
	Connection   *ovirtsdk.Connection
	ClusterId    string
	TemplateName string
	MachineName  string
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

func GetOvirtConnectionConf() (*ovirtsdk.ConnectionBuilder, error) {

	//// expecting ovirt-config.yaml at ~/.ovirt/ovirt-config.yaml or at env VAR OVIRT_CONFIG
	//file, err := os.Open("~/.ovirt/ovirt-config.yaml")

	//getCredentialsSecret()
	connectionBuilder := ovirtsdk.NewConnectionBuilder()

	// just for debug
	//klog.Infof("the ovirt config loaded is: %v", out)
	engineUrl := "https://rgolan.usersys.redhat.com:8443/ovirt-engine/api"
	connectionBuilder.
		URL(engineUrl).
		Username("admin@internal").
		Password("123").
		CAFile("")

	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	certURL, _ := url.Parse(engineUrl)
	certURL.Path = "ovirt-engine/services/pki-resource"
	certURL.RawQuery = url.PathEscape("resource=ca-certificate&format=X509-PEM-CA")

	resp, err := client.Get(certURL.String())
	if err != nil || resp.StatusCode != http.StatusOK {
		return connectionBuilder, fmt.Errorf("error downloading ovirt-engine certificate %s with status %v", err, resp)
	}
	defer resp.Body.Close()

	file, err := os.Create("/tmp/ovirt-engine.ca")
	if err != nil {
		return connectionBuilder, fmt.Errorf("failed writing ovirt-engine certificate %s", err)
	}
	io.Copy(file, resp.Body)
	connectionBuilder.CAFile(file.Name())
	return connectionBuilder, nil
}

func NewInstanceServiceFromMachine(machine *machinev1.Machine, connection *ovirtsdk.Connection) (*InstanceService, error) {
	machineSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}

	service := &InstanceService{Connection: connection}
	service.ClusterId = machineSpec.ClusterId
	service.TemplateName = machineSpec.TemplateName
	service.MachineName = machine.Name
	return service, err
}

func (is *InstanceService) InstanceCreate(
	machine *machinev1.Machine,
	providerSpec *ovirtconfigv1.OvirtMachineProviderSpec,
	kubeClient *kubernetes.Clientset) (instance *Instance, err error) {

	if providerSpec == nil {
		return nil, fmt.Errorf("create Options need be specified to create instace")
	}

	userDataSecret, err := kubeClient.CoreV1().
		Secrets(machine.Namespace).
		Get(providerSpec.UserDataSecret.Name, v1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user data secret for the machine namespace: %s", err)
	}

	ignition, ok := userDataSecret.Data["userData"]
	if !ok {
		return nil, fmt.Errorf("failed extracting ignition from user data secret %v", string(ignition))
	}
	cluster := ovirtsdk.NewClusterBuilder().Id(providerSpec.ClusterId).MustBuild()
	template := ovirtsdk.NewTemplateBuilder().Name(providerSpec.TemplateName).MustBuild()
	cpu := ovirtsdk.NewCpuBuilder().
		TopologyBuilder(
			ovirtsdk.NewCpuTopologyBuilder().
			Cores(int64(providerSpec.Cores)).
			Sockets(int64(providerSpec.Sockets)).
			Threads(int64(providerSpec.Threads))).
		MustBuild()
	init := ovirtsdk.NewInitializationBuilder().
		CustomScript(string(ignition)).
		HostName(machine.Name).
		MustBuild()
	vm, err := ovirtsdk.NewVmBuilder().
		Name(machine.Name).
		Cluster(cluster).
		Template(template).
		Cpu(cpu).
		Memory(int64(providerSpec.MemoryInMB * int32(math.Pow(2, 20)))).
		Type(providerSpec.InstanceType).
		Initialization(init).
		Build()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct VM struct")
	}

	klog.Infof("creating VM: %v", vm.MustName())
	response, err := is.Connection.SystemService().VmsService().Add().Vm(vm).Send()
	if err != nil {
		klog.Errorf("Failed creating VM", err)
		return nil, err
	}

	_, err = is.Connection.SystemService().VmsService().
		VmService(response.MustVm().MustId()).
		TagsService().Add().
		Tag(ovirtsdk.NewTagBuilder().Name(machine.Labels["machine.openshift.io/cluster-api-cluster"]).MustBuild()).
		Send()
	if err != nil {
		klog.Errorf("Failed to add tag to  VM, skipping", err)
	}

	return &Instance{response.MustVm()}, nil
}

func (is *InstanceService) InstanceDelete(id string) error {
	klog.Infof("Deleting VM with ID: %s", id)
	vmService := is.Connection.SystemService().VmsService().VmService(id)
	_, err := vmService.Stop().Send()
	if err != nil {
		return err
	}
	err = util.PollImmediate(time.Second * 10, time.Minute * 5, func() (bool, error) {
		vmResponse, err := vmService.Get().Send()
		if err != nil {
			return false, nil
		}
		vm, ok := vmResponse.Vm()
		if !ok {
			return false, err
		}

		return  vm.MustStatus() == ovirtsdk.VMSTATUS_DOWN, nil
	})
	_, err = vmService.Remove().Send()

	// poll till VM doesn't exist
	err = util.PollImmediate(time.Second * 10, time.Minute * 5, func() (bool, error) {
		_, err := vmService.Get().Send()
		return  err != nil, nil
	})
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
		klog.Infof("Search return %d vms", len(vms.Slice()))
		for _, vm := range vms.Slice() {
			if cluster, ok := vm.Cluster(); ok {
				id, _ := cluster.Id()
				if id == is.ClusterId {
					name, _ := vm.Name()
					klog.V(5).Infof("Found VM: %v", name)
					instanceList = append(instanceList, &Instance{Vm: vm})
				}
			}
		}
	}
	return instanceList, nil
}

// Get VM by ID or Name
func (is *InstanceService) GetVm(machine machinev1.Machine) (instance *Instance, err error) {
	if machine.Spec.ProviderID != nil && *machine.Spec.ProviderID != "" {
		klog.Infof("Fetching VM by ID: %s", machine.Spec.ProviderID)
		instance, err = is.GetVmByID(*machine.Spec.ProviderID)
		if err == nil {
			return instance, err
		}
	}
	instance, err = is.GetVmByName()
	return instance, err

}

func (is *InstanceService) GetVmByID(resourceId string) (instance *Instance, err error) {
	klog.Infof("Fetching VM by ID: %s", resourceId)
	if resourceId == "" {
		return nil, fmt.Errorf("ResourceId should be specified to get detail")
	}
	response, err := is.Connection.SystemService().VmsService().VmService(resourceId).Get().Send()
	if err != nil {
		return nil, err
	}
	klog.Infof("Got VM by ID: %s", response.MustVm().MustName())
	return &Instance{Vm: response.MustVm()}, nil
}

func (is *InstanceService) GetVmByName() (*Instance, error) {
	response, err := is.Connection.SystemService().VmsService().
		List().Search("name=" + is.MachineName).Send()
	if err != nil {
		klog.Errorf("Failed to fetch VM by name")
		return nil, err
	}
	for _, vm := range response.MustVms().Slice() {
		if name, ok := vm.Name(); ok {
			if name == is.MachineName {
				return &Instance{Vm: vm}, nil
			}
		}
	}
	// returning an nil instance if we didn't find a match
	return nil, nil
}
