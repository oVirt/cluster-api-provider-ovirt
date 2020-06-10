/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"

	apicorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OvirtCreds struct {
	URL      string
	Username string
	Password string
	CAFile   string
	Insecure bool
	CABundle string
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
	insecure, err := strconv.ParseBool(string(credentialsSecret.Data["ovirt_insecure"]))
	if err == nil {
		o.Insecure = insecure
	}
	o.CABundle = string(credentialsSecret.Data["ovirt_ca_bundle"])

	// write CA bundle to a file if exist.
	// its best if we could mount the secret into a file,
	// but this controller deployment cannot
	if o.CABundle != "" {
		caFilePath, err := writeCA(strings.NewReader(o.CABundle))
		if err != nil {
			klog.Errorf("failed to extract and store the CA %s", err)
			return nil, err
		}
		o.CAFile = caFilePath
	}
	return &o, nil
}

func writeCA(source io.Reader) (string, error) {
	f, err := ioutil.TempFile("", "ovirt-ca-bundle")
	if err != nil {
		return "", err
	}
	defer f.Close()
	content, err := ioutil.ReadAll(source)
	if err != nil {
		return "", err
	}
	_, err = f.Write(content)
	if err != nil {
		return "", err
	}
	return f.Name(), nil
}
