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

	"k8s.io/apimachinery/pkg/runtime/serializer/json"

	"k8s.io/apimachinery/pkg/runtime/schema"
	clusterv1 "github.com/openshift/cluster-api/pkg/apis/cluster/v1alpha1"
	//machinev1 "github.com/openshift/cluster-api/pkg/apis/machine/v1beta1"
	"github.com/openshift/cluster-api/pkg/util"
)

// Long term, we should retrieve the current status by asking k8s, openstack etc. for all the needed info.
// For now, it is stored in the matching CRD under an annotation. This is similar to
// the spec and status concept where the machine CRD is the instance spec and the annotation is the instance status.

const InstanceStatusAnnotationKey = "instance-status"

type instanceStatus *clusterv1.Machine

// Get the status of the instance identified by the given machine
func (ovirtClient *OvirtClient) instanceStatus(machine *clusterv1.Machine) (instanceStatus, error) {
	currentMachine, err := util.GetMachineIfExists(ovirtClient.client, machine.Namespace, machine.Name)
	if err != nil {
		return nil, err
	}

	if currentMachine == nil {
		// The current status no longer exists because the matching CRD has been deleted (or does not exist yet ie. bootstrapping)
		return nil, nil
	}
	return ovirtClient.machineInstanceStatus(currentMachine)
}

// Sets the status of the instance identified by the given machine to the given machine
func (ovirtClient *OvirtClient) updateInstanceStatus(machine *clusterv1.Machine) error {
	status := instanceStatus(machine)
	currentMachine, err := util.GetMachineIfExists(ovirtClient.client, machine.Namespace, machine.Name)
	if err != nil {
		return err
	}

	if currentMachine == nil {
		// The current status no longer exists because the matching CRD has been deleted.
		return fmt.Errorf("Machine has already been deleted. Cannot update current instance status for machine %v", machine.ObjectMeta.Name)
	}

	m, err := ovirtClient.setMachineInstanceStatus(currentMachine, status)
	if err != nil {
		return err
	}

	return ovirtClient.client.Update(nil, m)
}

// Gets the state of the instance stored on the given machine CRD
func (ovirtClient *OvirtClient) machineInstanceStatus(machine *clusterv1.Machine) (instanceStatus, error) {
	if machine.ObjectMeta.Annotations == nil {
		// No state
		return nil, nil
	}

	a := machine.ObjectMeta.Annotations[InstanceStatusAnnotationKey]
	if a == "" {
		// No state
		return nil, nil
	}

	serializer := json.NewSerializer(json.DefaultMetaFactory, ovirtClient.scheme, ovirtClient.scheme, false)
	var status clusterv1.Machine
	_, _, err := serializer.Decode([]byte(a), &schema.GroupVersionKind{Group: "cluster.k8s.io", Version: "v1alpha1", Kind: "Machine"}, &status)
	if err != nil {
		return nil, fmt.Errorf("decoding failure: %v", err)
	}

	return instanceStatus(&status), nil
}

// Applies the state of an instance onto a given machine CRD
func (ovirtClient *OvirtClient) setMachineInstanceStatus(machine *clusterv1.Machine, status instanceStatus) (*clusterv1.Machine, error) {
	// Avoid status within status within status ...
	status.ObjectMeta.Annotations[InstanceStatusAnnotationKey] = ""

	serializer := json.NewSerializer(json.DefaultMetaFactory, ovirtClient.scheme, ovirtClient.scheme, false)
	b := []byte{}
	buff := bytes.NewBuffer(b)
	err := serializer.Encode((*clusterv1.Machine)(status), buff)
	if err != nil {
		return nil, fmt.Errorf("encoding failure: %v", err)
	}

	if machine.ObjectMeta.Annotations == nil {
		machine.ObjectMeta.Annotations = make(map[string]string)
	}
	machine.ObjectMeta.Annotations[InstanceStatusAnnotationKey] = buff.String()
	return machine, nil
}
