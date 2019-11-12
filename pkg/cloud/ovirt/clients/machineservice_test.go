/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"strings"
	"testing"

	ovirtsdk "github.com/ovirt/go-ovirt"
)

func TestMachineServiceInstance(t *testing.T) {
	builder := ovirtsdk.NewConnectionBuilder().
		URL("test.url").
		Username("testusername@internal").
		Password("123")
	_, err := NewInstanceServiceFromConf(builder)
	if !(strings.Contains(err.Error(), "[auth_url]")) {
		t.Errorf("Couldn't create instance service: %v", err)
	}
}
