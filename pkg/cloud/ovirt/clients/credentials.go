/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"context"
	"fmt"
	"strconv"

	apicorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OvirtCreds struct {
	URL      string
	Username string
	Password string
	CAFile   string
	Insecure bool
}

func GetCredentialsSecret(coreClient client.Client, namespace string, secretName string) (*OvirtCreds, error) {
	var credentialsSecret apicorev1.Secret
	key := client.ObjectKey{Namespace: namespace, Name: secretName}

	if err := coreClient.Get(context.Background(), key, &credentialsSecret); err != nil {
		if errors.IsNotFound(err) {
			return nil, fmt.Errorf("error getting credentials secret %q in namespace %q: %v", secretName, namespace, err)
		}
		return nil, err
	}

	o := OvirtCreds{}
	o.URL = string(credentialsSecret.Data["ovirt_url"])
	o.Username = string(credentialsSecret.Data["ovirt_username"])
	o.Password = string(credentialsSecret.Data["ovirt_password"])
	o.CAFile = string(credentialsSecret.Data["ovirt_cafile"])
	insecure, err  := strconv.ParseBool(string(credentialsSecret.Data["ovirt_insecure"]))
	if err == nil {
		o.Insecure = insecure
	}

	return &o, nil
}

