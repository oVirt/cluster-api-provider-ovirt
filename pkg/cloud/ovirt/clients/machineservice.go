/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"fmt"
	"math"
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
	init := ovirtsdk.NewInitializationBuilder().
		CustomScript(string(ignition)).
		HostName(machine.Name).
		MustBuild()

	vmBuilder := ovirtsdk.NewVmBuilder().
		Name(machine.Name).
		Cluster(cluster).
		Template(template).
		Initialization(init)

	if providerSpec.VMType != "" {
		vmBuilder.Type(ovirtsdk.VmType(providerSpec.VMType))
	}
	if providerSpec.InstanceTypeId != "" {
		vmBuilder.InstanceTypeBuilder(
			ovirtsdk.NewInstanceTypeBuilder().
				Id(providerSpec.InstanceTypeId))
	} else {
		if providerSpec.CPU != nil {
			vmBuilder.CpuBuilder(
				ovirtsdk.NewCpuBuilder().
					TopologyBuilder(ovirtsdk.NewCpuTopologyBuilder().
						Cores(int64(providerSpec.CPU.Cores)).
						Sockets(int64(providerSpec.CPU.Sockets)).
						Threads(int64(providerSpec.CPU.Threads))))
		}
		if providerSpec.MemoryMB > 0 {
			vmBuilder.Memory(int64(math.Pow(2, 20)) * int64(providerSpec.MemoryMB))
		}
	}

	vm, err := vmBuilder.Build()
	if err != nil {
		return nil, errors.Wrap(err, "Failed to construct VM struct")
	}

	klog.Infof("creating VM: %v", vm.MustName())
	response, err := is.Connection.SystemService().VmsService().Add().Vm(vm).Send()
	if err != nil {
		klog.Errorf("Failed creating VM", err)
		return nil, err
	}

	err = is.Connection.WaitForVM(response.MustVm().MustId(), ovirtsdk.VMSTATUS_DOWN, time.Minute)
	if err != nil {
		return nil, errors.Wrap(err, "Timed out waiting for the VM creation to finish")
	}

	vmService := is.Connection.SystemService().VmsService().VmService(response.MustVm().MustId())

	if providerSpec.OSDisk != nil {
		err = is.handleDiskExtension(vmService, response, providerSpec)
		if err != nil {
			return nil, err
		}
	}

	err = is.handleNics(vmService, providerSpec)
	if err != nil {
		return nil, errors.Wrapf(err, "failed handling nics creation for VM %s", vm.MustName())
	}

	_, err = is.Connection.SystemService().VmsService().
		VmService(response.MustVm().MustId()).
		TagsService().Add().
		Tag(ovirtsdk.NewTagBuilder().Name(machine.Labels["machine.openshift.io/cluster-api-cluster"]).MustBuild()).
		Send()
	if err != nil {
		klog.Errorf("Failed to add tag to VM, skipping", err)
	}

	return &Instance{response.MustVm()}, nil
}

func (is *InstanceService) handleDiskExtension(vmService *ovirtsdk.VmService, createdVM *ovirtsdk.VmsServiceAddResponse, providerSpec *ovirtconfigv1.OvirtMachineProviderSpec) error {
	attachmentsResponse, err := vmService.DiskAttachmentsService().List().Send()
	if err != nil {
		return err
	}

	var bootableDiskAttachment *ovirtsdk.DiskAttachment
	for _, disk := range attachmentsResponse.MustAttachments().Slice() {
		if disk.MustBootable() {
			// found the os disk
			bootableDiskAttachment = disk
		}
	}
	if bootableDiskAttachment == nil {
		return fmt.Errorf("the VM %s(%s) doesn't have a bootable disk - was Blank template used by mistake?",
			createdVM.MustVm().MustName(), createdVM.MustVm().MustId())
	}
	// extend the disk if requested size is bigger than template. We won't support shrinking it.
	newDiskSize := providerSpec.OSDisk.SizeGB * int64(math.Pow(2, 30))
	if newDiskSize > bootableDiskAttachment.MustDisk().MustProvisionedSize() {
		klog.Infof("Extending the OS disk from %d to %d",
			bootableDiskAttachment.MustDisk().MustProvisionedSize(),
			newDiskSize)

		bootableDiskAttachment.
			MustDisk().
			SetProvisionedSize(newDiskSize)
		_, err := vmService.DiskAttachmentsService().
			AttachmentService(bootableDiskAttachment.MustDisk().MustId()).
			Update().
			Send()
		if err != nil {
			return err
		}
		klog.Infof("Waiting while extending the OS disk")
		// wait for the disk extension to be over
		err = is.Connection.WaitForDisk(bootableDiskAttachment.MustId(), ovirtsdk.DISKSTATUS_OK, 20*time.Minute)
		if err != nil {
			return err
		}
	}
	return nil
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

func (is *InstanceService) handleNics(vmService *ovirtsdk.VmService, spec *ovirtconfigv1.OvirtMachineProviderSpec) error {
	if spec.NetworkInterfaces == nil || len(spec.NetworkInterfaces) == 0 {
		return nil
	}
	nicList, err := vmService.NicsService().List().Send()
	if err != nil {
		return errors.Wrap(err, "failed fetching VM network interfaces")
	}

	// remove all existing nics
	for _, n := range nicList.MustNics().Slice() {
		_, err := vmService.NicsService().NicService(n.MustId()).Remove().Send()
		if err != nil {
			return errors.Wrap(err, "failed clearing all interfaces before populating new ones")
		}
	}

	// re-add nics
	for i, nic := range spec.NetworkInterfaces {
		_, err := vmService.NicsService().Add().Nic(
			ovirtsdk.NewNicBuilder().
				Name(fmt.Sprintf("nic%d", i+1)).
				VnicProfileBuilder(ovirtsdk.NewVnicProfileBuilder().Id(nic.VNICProfileID)).
				MustBuild()).
			Send()
		if err != nil {
			return errors.Wrap(err, "failed to create network interface")
		}
	}
	return nil
}
