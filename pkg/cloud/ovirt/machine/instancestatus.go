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
	"bytes"
	"fmt"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/klog"

	machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

const InstanceStatusAnnotationKey = "instance-status"

type instanceStatus *machinev1.Machine

// Get the status of the instance identified by the given machine
func (actuator *OvirtActuator) instanceStatus(machine *machinev1.Machine) (instanceStatus, error) {
	currentMachine, err := actuator.machinesClient.Machines("openshift-machine-api").Get(machine.Name, v1.GetOptions{})
	if err != nil {
		klog.Errorf("Didn't find machine with namespace: %s and name: %s", machine.Namespace, machine.Name)
		return nil, err
	}

	klog.Infof("Found machine %s", currentMachine.Name)
	if currentMachine == nil {
		// The current status no longer exists because the matching CRD has been deleted (or does not exist yet ie. bootstrapping)
		return nil, nil
	}
	return actuator.machineInstanceStatus(currentMachine)
}

// Sets the status of the instance identified by the given machine to the given machine
func (actuator *OvirtActuator) updateInstanceStatus(machine *machinev1.Machine) error {
	status := instanceStatus(machine)
	currentMachine, err := actuator.machinesClient.Machines("openshift-machine-api").Get(machine.Name, v1.GetOptions{})
	if err != nil {
		return err
	}

	if currentMachine == nil {
		// The current status no longer exists because the matching CRD has been deleted.
		return fmt.Errorf("machine has already been deleted - cannot update current instance status for machine %v", machine.ObjectMeta.Name)
	}

	m, err := actuator.setMachineInstanceStatus(currentMachine, status)
	if err != nil {
		return err
	}

	return actuator.client.Update(nil, m)
}

// Gets the state of the instance stored on the given machine CRD
func (actuator *OvirtActuator) machineInstanceStatus(machine *machinev1.Machine) (instanceStatus, error) {
	if machine.ObjectMeta.Annotations == nil {
		// No state
		return nil, nil
	}

	a := machine.ObjectMeta.Annotations[InstanceStatusAnnotationKey]
	if a == "" {
		// No state
		return nil, nil
	}

	serializer := json.NewSerializer(json.DefaultMetaFactory, actuator.scheme, actuator.scheme, false)
	var status machinev1.Machine
	_, _, err := serializer.Decode([]byte(a), &schema.GroupVersionKind{Group: "machine.openshift.io", Version: "v1beta1", Kind: "Machine"}, &status)
	if err != nil {
		return nil, fmt.Errorf("decoding failure: %v", err)
	}

	return &status, nil
}

// Applies the state of an instance onto a given machine CRD
func (actuator *OvirtActuator) setMachineInstanceStatus(machine *machinev1.Machine, status instanceStatus) (*machinev1.Machine, error) {
	// Avoid status within status within status ...
	status.ObjectMeta.Annotations[InstanceStatusAnnotationKey] = ""

	serializer := json.NewSerializer(json.DefaultMetaFactory, actuator.scheme, actuator.scheme, false)
	b := []byte{}
	buff := bytes.NewBuffer(b)
	err := serializer.Encode((*machinev1.Machine)(status), buff)
	if err != nil {
		return nil, fmt.Errorf("encoding failure: %v", err)
	}

	if machine.ObjectMeta.Annotations == nil {
		machine.ObjectMeta.Annotations = make(map[string]string)
	}
	machine.ObjectMeta.Annotations[InstanceStatusAnnotationKey] = buff.String()
	return machine, nil
}
