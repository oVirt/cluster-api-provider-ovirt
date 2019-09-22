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

package machine

import (
	"context"
	"fmt"
	"reflect"
	"time"

	clusterv1 "github.com/openshift/cluster-api/pkg/apis/cluster/v1alpha1"
	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/klog"

	ovirtconfigv1 "github.com/ovirt/cluster-api-provider-ovirt/pkg/apis/ovirtclusterproviderconfig/v1alpha1"
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

type SshCreds struct {
	user           string
	privateKeyPath string
	publicKey      string
}

type OvirtClient struct {
	params ovirt.ActuatorParams
	scheme *runtime.Scheme
	client client.Client
}

func NewActuator(params ovirt.ActuatorParams) (*OvirtClient, error) {
	return &OvirtClient{
		params:           params,
		client:           params.Client,
		scheme:           params.Scheme,
	}, nil
}

func (ovirtClient *OvirtClient) Create(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	kubeClient := ovirtClient.params.KubeClient

	machineService, err := clients.NewInstanceServiceFromMachine(kubeClient, machine)
	if err != nil {
		return err
	}

	providerSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return ovirtClient.handleMachineError(machine, apierrors.InvalidMachineConfiguration(
			"Cannot unmarshal providerSpec field: %v", err))
	}

	if verr := ovirtClient.validateMachine(machine, providerSpec); verr != nil {
		return ovirtClient.handleMachineError(machine, verr)
	}

	instance, err := ovirtClient.instanceExists(machine)
	if err != nil {
		return err
	}
	if instance != nil {
		klog.Infof("Skipped creating a VM that already exists.\n")
		return nil
	}

	instance, err = machineService.InstanceCreate(machine.Name, providerSpec)
	if err != nil {
		return ovirtClient.handleMachineError(machine, apierrors.CreateMachine(
			"error creating Ovirt instance: %v", err))
	}
	// TODO: wait instance ready
	err = util.PollImmediate(RetryIntervalInstanceStatus, TimeoutInstanceCreate, func() (bool, error) {
		instance, err := machineService.GetInstance(instance.Id)
		if err != nil {
			return false, nil
		}
		return instance.Status == "ACTIVE", nil
	})
	if err != nil {
		return ovirtClient.handleMachineError(machine, apierrors.CreateMachine(
			"error creating Ovirt instance: %v", err))
	}


	return ovirtClient.updateAnnotation(machine, instance.Id)
}

func (ovirtClient *OvirtClient) Delete(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	machineService, err := clients.NewInstanceServiceFromMachine(ovirtClient.params.KubeClient, machine)
	if err != nil {
		return err
	}

	instance, err := ovirtClient.instanceExists(machine)
	if err != nil {
		return err
	}

	if instance == nil {
		klog.Infof("Skipped deleting a VM that is already deleted.\n")
		return nil
	}

	id := machine.ObjectMeta.Annotations[ovirt.OvirtIdAnnotationKey]
	err = machineService.InstanceDelete(id)
	if err != nil {
		return ovirtClient.handleMachineError(machine, apierrors.DeleteMachine(
			"error deleting Ovirt instance: %v", err))
	}

	return nil
}

func (ovirtClient *OvirtClient) Update(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) error {
	status, err := ovirtClient.instanceStatus(machine)
	if err != nil {
		return err
	}

	currentMachine := status
	if currentMachine == nil {
		instance, err := ovirtClient.instanceExists(machine)
		if err != nil {
			return err
		}
		if instance != nil && instance.Status == "ACTIVE" {
			klog.Infof("Populating current state for boostrap machine %v", machine.ObjectMeta.Name)
			return ovirtClient.updateAnnotation(machine, instance.Id)
		} else {
			return fmt.Errorf("Cannot retrieve current state to update machine %v", machine.ObjectMeta.Name)
		}
	}

	if !ovirtClient.requiresUpdate(currentMachine, machine) {
		return nil
	}

	klog.Infof("re-creating machine %s for update.", currentMachine.ObjectMeta.Name)
	err = ovirtClient.Delete(ctx, cluster, currentMachine)
	if err != nil {
		klog.Errorf("delete machine %s for update failed: %v", currentMachine.ObjectMeta.Name, err)
	} else {
		//TODO rgolan - wait a bit between delete + create?
		err = ovirtClient.Create(ctx, cluster, machine)
		if err != nil {
			klog.Errorf("create machine %s for update failed: %v", machine.ObjectMeta.Name, err)
		}
	}

	return nil
}

func (ovirtClient *OvirtClient) Exists(ctx context.Context, cluster *clusterv1.Cluster, machine *machinev1.Machine) (bool, error) {
	instance, err := ovirtClient.instanceExists(machine)
	if err != nil {
		return false, err
	}
	return instance != nil, err
}

func getIPFromInstance(instance *clients.Instance) (string, error) {
	type networkInterface struct {
		Address string  `json:"addr"`
		Version float64 `json:"version"`
		Type    string  `json:"OS-EXT-IPS:type"`
	}

	if len(instance.Nics.Nics) == 0 {
		return "", fmt.Errorf("the instance %s has no reported interaces", instance.Name)
	}

	// The ovirt-guest agent reports all ips. It is possible to blacklist
	// some devices from the report. Specifically to get the public ip address
	// we don't have a reliable way other than heuristics to get an accessible public ip
	// possibly match it against the current network
	for _, nic := range instance.Nics.Nics {
			for _, device := range nic.Devices.Devices {
				for _, ip := range  device.Ips.Ips {
					if ip.Version == "v4" {
						return ip.Address, nil
					}
				}
			}
	}

	return "", fmt.Errorf("extract IP from instance err")
}

// If the OvirtClient has a client for updating Machine objects, this will set
// the appropriate reason/message on the Machine.Status. If not, such as during
// cluster installation, it will operate as a no-op. It also returns the
// original error for convenience, so callers can do "return handleMachineError(...)".
func (ovirtClient *OvirtClient) handleMachineError(machine *machinev1.Machine, err *apierrors.MachineError) error {
	if ovirtClient.client != nil {
		machine.Status.ErrorReason = &err.Reason
		machine.Status.ErrorMessage = &err.Message
		if err := ovirtClient.client.Update(nil, machine); err != nil {
			return fmt.Errorf("unable to update machine status: %v", err)
		}
	}

	klog.Errorf("Machine error %s: %v", machine.Name, err.Message)
	return err
}

func (ovirtClient *OvirtClient) updateAnnotation(machine *machinev1.Machine, id string) error {
	if machine.ObjectMeta.Annotations == nil {
		machine.ObjectMeta.Annotations = make(map[string]string)
	}
	machine.ObjectMeta.Annotations[ovirt.OvirtIdAnnotationKey] = id

	if err := ovirtClient.client.Update(nil, machine); err != nil {
		return err
	}
	return ovirtClient.updateInstanceStatus(machine)
}

func (ovirtClient *OvirtClient) requiresUpdate(a *machinev1.Machine, b *machinev1.Machine) bool {
	if a == nil || b == nil {
		return true
	}
	// Do not want status changes. Do want changes that impact machine provisioning
	return !reflect.DeepEqual(a.Spec.ObjectMeta, b.Spec.ObjectMeta) ||
		!reflect.DeepEqual(a.Spec.ProviderSpec, b.Spec.ProviderSpec) ||
		a.ObjectMeta.Name != b.ObjectMeta.Name
}

func (ovirtClient *OvirtClient) instanceExists(machine *machinev1.Machine) (instance *clients.Instance, err error) {
	machineSpec, err := ovirtconfigv1.MachineSpecFromProviderSpec(machine.Spec.ProviderSpec)
	if err != nil {
		return nil, err
	}
	opts := &clients.InstanceListOpts{
		Name:   machineSpec.Name,
	}

	machineService, err := clients.NewInstanceServiceFromMachine(ovirtClient.params.KubeClient, machine)
	if err != nil {
		return nil, err
	}

	instanceList, err := machineService.GetInstanceList(opts)
	if err != nil {
		return nil, err
	}
	if len(instanceList) == 0 {
		return nil, nil
	}
	return instanceList[0], nil
}

func (ovirtClient *OvirtClient) validateMachine(machine *machinev1.Machine, config *ovirtconfigv1.OvirtMachineProviderSpec) *apierrors.MachineError {
	return nil
}
