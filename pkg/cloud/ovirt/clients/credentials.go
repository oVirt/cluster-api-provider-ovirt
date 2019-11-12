/*
Copyright oVirt Authors
SPDX-License-Identifier: Apache-2.0
*/

package clients

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"

	apicorev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

type OvirtCreds struct {
	URL      string
	Username string
	Password string
	CAFile   string
}

func GetCredentialsSecret(coreClient client.Client, namespace string, secretName string) (OvirtCreds, error) {
	var credentialsSecret apicorev1.Secret
	key := client.ObjectKey{Namespace: namespace, Name: secretName}

	if err := coreClient.Get(context.Background(), key, &credentialsSecret); err != nil {
		if errors.IsNotFound(err) {
			return OvirtCreds{}, fmt.Errorf("error getting credentials secret %q in namespace %q: %v", secretName, namespace, err)
		}
	}

	o := OvirtCreds{}
	o.URL = string(credentialsSecret.Data["ovirt_url"])
	o.Username = string(credentialsSecret.Data["ovirt_username"])
	o.Password = string(credentialsSecret.Data["ovirt_password"])
	o.CAFile = string(credentialsSecret.Data["ovirt_cafile"])
	if o.CAFile == "" {
		cafile, err := fetchCAPathFromURL(o.URL)
		if err != nil {
			return OvirtCreds{}, err
		}
		o.CAFile = cafile
	}
	return o, nil
}

func fetchCAPathFromURL(engineUrl string) (string, error){
	client := http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	certURL, _ := url.Parse(engineUrl)
	certURL.Path = "ovirt-engine/services/pki-resource"
	certURL.RawQuery = url.PathEscape("resource=ca-certificate&format=X509-PEM-CA")

	resp, err := client.Get(certURL.String())
	if err != nil || resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("error downloading ovirt-engine certificate %s with status %v", err, resp)
	}

	file, err := os.Create("/tmp/ovirt-engine.ca")
	if err != nil {
		return "", fmt.Errorf("failed writing ovirt-engine certificate %s", err)
	}
	io.Copy(file, resp.Body)
	defer file.Close()
	return file.Name(), nil



}
