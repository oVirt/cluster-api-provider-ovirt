/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package machine

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"time"

	clusterv1 "github.com/openshift/cluster-api/pkg/apis/cluster/v1alpha1"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/openshift/cluster-api/pkg/client/clientset_generated/clientset/typed/machine/v1beta1"
	ovirtsdk "github.com/ovirt/go-ovirt"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/record"
	"k8s.io/klog"

	ovirtconfigv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtprovider/v1beta1"
	"github.com/ovirt/cluster-api-provider-ovirt/pkg/cloud/ovirt"
	"github.com/ovirt/cluster-api-provider-ovirt/pkg/cloud/ovirt/clients"

	apierrors "github.com/openshift/cluster-api/pkg/errors"
	"github.com/openshift/cluster-api/pkg/util"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

const (
	TimeoutInstanceCreate       = 5 * time.Minute
	RetryIntervalInstanceStatus = 10 * time.Second
)

type OvirtActuator struct {
	params         ovirt.ActuatorParams
	scheme         *runtime.Scheme
	client         client.Client
	KubeClient     *kubernetes.Clientset
	machinesClient v1beta1.MachineV1beta1Interface
	EventRecorder  record.EventRecorder
}

func NewActuator(params ovirt.ActuatorParams) (*OvirtActuator, error) {
	return &OvirtActuator{
		params:         params,
		client:         params.Client,
		machinesClient: params.MachinesClient,
		scheme:         params.Scheme,
		KubeClient:     params.KubeClient,
		EventRecorder:  params.EventRecorder,
	}, nil
}

//getConnection returns a a client to oVirt's API endpoint
func (actuator *OvirtActuator) getConnection(namespace, secretName string) (*ovirtsdk.Connection, error) {

	creds, err := clients.GetCredentialsSecret(actuator.client, namespace, secretName)
	if err != nil {
		klog.Infof("failed getting creadentials for namespace %s, %s", namespace, err)
		return nil, err
	}

	connection, err := ovirtsdk.NewConnectionBuilder().
		URL(creds.URL).
		Username(creds.Username).
		Password(creds.Password).
		CAFile(creds.CAFile).Build()
	if err != nil {
		return nil, err
	}

	return connection, nil
}

func (actuator *OvirtActuator) Create(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	providerSpec, err := ovirtconfigv1.ProviderSpecFromRawExtension(machine.Spec.ProviderSpec.Value)
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot unmarshal providerSpec field: %v", err))
	}

	connection, err := actuator.getConnection(machine.Namespace, providerSpec.CredentialsSecret.Name)
	if err != nil {
		return fmt.Errorf("failed to create connection to oVirt API")
	}
	defer connection.Close()

	machineService, err := clients.NewInstanceServiceFromMachine(machine, connection)
	if err != nil {
		return err
	}

	if verr := actuator.validateMachine(machine, providerSpec); verr != nil {
		return actuator.handleMachineError(machine, verr)
	}

	// creating a new instance, we don't have the vm id yet
	instance, err := machineService.GetVmByName()
	if err != nil {
		return err
	}
	if instance != nil {
		klog.Infof("Skipped creating a VM that already exists.\n")
		return nil
	}

	instance, err = machineService.InstanceCreate(machine, providerSpec, actuator.KubeClient)
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.CreateMachine(
			"error creating Ovirt instance: %v", err))
	}

	// Wait till ready
	err = util.PollImmediate(RetryIntervalInstanceStatus, TimeoutInstanceCreate, func() (bool, error) {
		instance, err := machineService.GetVm(instance.MustId())
		if err != nil {
			return false, nil
		}
		return instance.MustStatus() == ovirtsdk.VMSTATUS_DOWN, nil
	})
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.CreateMachine(
			"Error creating oVirt VM: %v", err))
	}

	vmService := machineService.Connection.SystemService().VmsService().VmService(instance.MustId())
	_, err = vmService.Start().Send()
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.CreateMachine(
			"Error running oVirt VM: %v", err))
	}

	// Wait till running
	err = util.PollImmediate(RetryIntervalInstanceStatus, TimeoutInstanceCreate, func() (bool, error) {
		instance, err := machineService.GetVm(instance.MustId())
		if err != nil {
			return false, nil
		}
		return instance.MustStatus() == ovirtsdk.VMSTATUS_UP, nil
	})
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.CreateMachine(
			"Error running oVirt VM: %v", err))
	}

	actuator.EventRecorder.Eventf(machine, corev1.EventTypeNormal, "Created", "Updated Machine %v", machine.Name)
	return actuator.updateAnnotation(machine, instance)
}

func (actuator *OvirtActuator) Exists(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) (bool, error) {
	providerSpec, err := ovirtconfigv1.ProviderSpecFromRawExtension(machine.Spec.ProviderSpec.Value)
	if err != nil {
		return false, actuator.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot unmarshal providerSpec field: %v", err))
	}

	connection, err := actuator.getConnection(machine.Namespace, providerSpec.CredentialsSecret.Name)
	if err != nil {
		return false, fmt.Errorf("failed to create connection to oVirt API")
	}
	defer connection.Close()

	machineService, err := clients.NewInstanceServiceFromMachine(machine, connection)
	if err != nil {
		return false, err
	}
	byName, err := machineService.GetVmByName()
	if err != nil {
		return false, err
	}
	return byName != nil, err
}

func (actuator *OvirtActuator) Update(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	klog.Infof("About to update machine %s", machine.Name)
	_, err := actuator.instanceStatus(machine)
	if err != nil {
		return err
	}

	// eager update
	providerSpec, err := ovirtconfigv1.ProviderSpecFromRawExtension(machine.Spec.ProviderSpec.Value)
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot unmarshal providerSpec field: %v", err))
	}

	connection, err := actuator.getConnection(machine.Namespace, providerSpec.CredentialsSecret.Name)
	if err != nil {
		return fmt.Errorf("failed to create connection to oVirt API")
	}
	defer connection.Close()

	machineService, err := clients.NewInstanceServiceFromMachine(machine, connection)
	if err != nil {
		return err
	}

	// we might not have the vm id updated on the machine spec yet, so get by name.
	byName, err := machineService.GetVmByName()
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot find a VM by name: %v", err))
	}
	return actuator.updateAnnotation(machine, byName)

	//currentMachine := status
	//if currentMachine == nil {
	//	instance, err := actuator.instanceExists(machine)
	//	if err != nil {
	//		return err
	//	}
	//	if instance != nil && instance.MustStatus() == ovirtsdk.VMSTATUS_UP {
	//		klog.Infof("Populating current state for boostrap machine %v", machine.ObjectMeta.Name)
	//		return actuator.updateAnnotation(machine, instance)
	//	} else {
	//		return fmt.Errorf("Cannot retrieve current state to update machine %v", machine.ObjectMeta.Name)
	//	}
	//}
	//
	//if !actuator.requiresUpdate(currentMachine, machine) {
	//	return nil
	//}
	//
	//klog.Infof("re-creating machine %s for update.", currentMachine.ObjectMeta.Name)
	//err = actuator.Delete(ctx, cluster, currentMachine)
	//if err != nil {
	//	klog.Errorf("delete machine %s for update failed: %v", currentMachine.ObjectMeta.Name, err)
	//} else {
	//	//TODO rgolan - wait till the machine is not retrieved and then create?
	//	err = actuator.Create(ctx, cluster, machine)
	//	if err != nil {
	//		klog.Errorf("create machine %s for update failed: %v", machine.ObjectMeta.Name, err)
	//	}
	//}
	//
	//return nil
}

func (actuator *OvirtActuator) Delete(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	providerSpec, err := ovirtconfigv1.ProviderSpecFromRawExtension(machine.Spec.ProviderSpec.Value)
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot unmarshal providerSpec field: %v", err))
	}
	connection, err := actuator.getConnection(machine.Namespace, providerSpec.CredentialsSecret.Name)
	if err != nil {
		return err
	}
	defer connection.Close()

	machineService, err := clients.NewInstanceServiceFromMachine(machine, connection)
	if err != nil {
		return err
	}

	instance, err := machineService.GetVmByName()
	if err != nil {
		return err
	}

	if instance == nil {
		klog.Infof("Skipped deleting a VM that is already deleted.\n")
		return nil
	}

	err = machineService.InstanceDelete(instance.MustId())
	if err != nil {
		return actuator.handleMachineError(machine, apierrors.DeleteMachine(
			"error deleting Ovirt instance: %v", err))
	}

	actuator.EventRecorder.Eventf(machine, corev1.EventTypeNormal, "Deleted", "Updated Machine %v", machine.Name)
	return nil
}

func getIPFromInstance(instance *clients.Instance) ([]string, error) {
	type networkInterface struct {
		Address string  `json:"addr"`
		Version float64 `json:"version"`
		Type    string  `json:"OS-EXT-IPS:type"`
	}

	nics, ok := instance.Nics()
	if !ok {
		return nil, errors.New("There are no reported nics")
	}

	var addresses []string
	// The ovirt-guest agent reports all ips. It is possible to blacklist
	// some devices from the report. Specifically to get the public ip address
	// we don't have a reliable way other than heuristics to get an accessible public ip
	// possibly match it against the current network
	for _, nic := range nics.Slice() {
		if devices, ok := nic.ReportedDevices(); ok {
			for _, device := range devices.Slice() {
				if ips, ok := device.Ips(); ok {
					for _, ip := range ips.Slice() {
						if address, ok := ip.Address(); ok {
							addresses = append(addresses, address)
						}
					}
				}
			}
		}
	}

	return addresses, nil
}

// If the OvirtActuator has a client for updating Machine objects, this will set
// the appropriate reason/message on the Machine.Status. If not, such as during
// cluster installation, it will operate as a no-op. It also returns the
// original error for convenience, so callers can do "return handleMachineError(...)".
func (actuator *OvirtActuator) handleMachineError(machine *machinev1.Machine, err *apierrors.MachineError) error {
	if actuator.client != nil {
		machine.Status.ErrorReason = &err.Reason
		machine.Status.ErrorMessage = &err.Message
		if err := actuator.client.Update(nil, machine); err != nil {
			return fmt.Errorf("unable to update machine status: %v", err)
		}
	}

	klog.Errorf("Machine error %s: %v", machine.Name, err.Message)
	return err
}

func (actuator *OvirtActuator) updateAnnotation(machine *machinev1.Machine, instance *clients.Instance) error {
	klog.Info("Updating machine status")
	id := instance.MustId()
	status := string(instance.MustStatus())
	name := instance.MustName()
	machine.Spec.ProviderID = &id

	if machine.ObjectMeta.Annotations == nil {
		machine.ObjectMeta.Annotations = make(map[string]string)
	}
	machine.ObjectMeta.Annotations[ovirt.OvirtIdAnnotationKey] = id

	//TODO rgolan missing addresses, we don't have qemu-qa for RHCOS yet
	// see https://bugzilla.redhat.com/show_bug.cgi?id=1764804
	//machine.Status.Addresses =
	providerStatus := ovirtconfigv1.OvirtMachineProviderStatus{}
	providerStatus.InstanceState = &status
	providerStatus.InstanceID = &name

	succeedCondition := ovirtconfigv1.OvirtMachineProviderCondition{
		Type:    ovirtconfigv1.MachineCreated,
		Reason:  "machineCreationSucceedReason",
		Message: "machineCreationSucceedMessage",
		Status:  corev1.ConditionTrue,
	}
	providerStatus.Conditions = append(providerStatus.Conditions, succeedCondition)
	rawExtension, err := ovirtconfigv1.RawExtensionFromProviderStatus(&providerStatus)
	if err != nil {
		return err
	}
	addresses := []corev1.NodeAddress{{Address: name, Type: corev1.NodeInternalDNS}}
	// RHCOS QEMU guest agent isn't available yet - https://bugzilla.redhat.com/show_bug.cgi?id=1764804
	// Till we have one we must get the IPs from the worker by trying to resolve it by its name.
	klog.V(5).Infof("using hostname %s to resolve addresses", name)
	ips, err := net.LookupIP(name)
	if err == nil {
		for _, ip := range ips {
			if ip.To4() != nil {
				addresses = append(addresses, corev1.NodeAddress{Type: corev1.NodeInternalIP, Address: ip.String()})
			}
		}
	}
	machine.Status.Addresses = addresses
	machine.Status.ProviderStatus = rawExtension
	time := metav1.Now()
	machine.Status.LastUpdated = &time
	if _, err := actuator.machinesClient.Machines("openshift-machine-api").UpdateStatus(machine); err != nil {
		return err
	}
	err = actuator.updateInstanceStatus(machine)
	actuator.EventRecorder.Eventf(machine, corev1.EventTypeNormal, "Update", "Updated Machine %v", machine.Name)
	return err
}

func (actuator *OvirtActuator) requiresUpdate(a *machinev1.Machine, b *machinev1.Machine) bool {
	if a == nil || b == nil {
		return true
	}
	// Do not want status changes. Do want changes that impact machine provisioning
	return !reflect.DeepEqual(a.Spec.ObjectMeta, b.Spec.ObjectMeta) ||
		!reflect.DeepEqual(a.Spec.ProviderSpec, b.Spec.ProviderSpec) ||
		a.ObjectMeta.Name != b.ObjectMeta.Name
}

func (actuator *OvirtActuator) validateMachine(machine *machinev1.Machine, config *ovirtconfigv1.OvirtMachineProviderSpec) *apierrors.MachineError {
	return nil
}
