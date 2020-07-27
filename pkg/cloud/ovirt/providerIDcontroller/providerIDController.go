package providerIDcontroller

import (
	"context"
	"fmt"

	"github.com/go-logr/logr"
	ovirtsdk "github.com/ovirt/go-ovirt"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/klog/klogr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	"sigs.k8s.io/controller-runtime/pkg/source"

	"github.com/openshift/cluster-api-provider-ovirt/pkg/cloud/ovirt/clients"
)

var _ reconcile.Reconciler = &providerIDReconciler{}

type providerIDReconciler struct {
	log                  logr.Logger
	client               client.Client
	listNodesByFieldFunc func(key, value string) ([]corev1.Node, error)
	fetchProviderIDFunc  func(string) (string, error)
	ovirtApi             *ovirtsdk.Connection
}

func (r *providerIDReconciler) Reconcile(request reconcile.Request) (reconcile.Result, error) {
	r.log.V(3).Info("Reconciling", "node", request.NamespacedName)

	// Fetch the Node instance
	node := corev1.Node{}
	err := r.client.Get(context.Background(), request.NamespacedName, &node)
	if err != nil {
		if errors.IsNotFound(err) {
			// Request object not found, could have been deleted after reconcile request.
			// Owned objects are automatically garbage collected. For additional cleanup logic use finalizers.
			// Return and don't requeue
			return reconcile.Result{}, nil
		}
		// Error reading the object - requeue the request.
		return reconcile.Result{}, fmt.Errorf("error getting node: %v", err)
	}

	if node.Spec.ProviderID != "" {
		return reconcile.Result{}, nil
	}

	r.log.Info("spec.ProviderID is empty, fetching from ovirt", "node", request.NamespacedName)
	id, err := r.fetchProviderIDFunc(node.Name)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed getting VM from oVirt: %v", err)
	}

	node.Spec.ProviderID = fmt.Sprintf("ovirt://%s", id)
	err = r.client.Update(context.Background(), &node)
	if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed updating node %s: %v", node.Name, err)
	}
	return reconcile.Result{}, nil
}

func (r *providerIDReconciler) fetchOvirtVmID(nodeName string) (string, error) {
	c, err := r.getConnection("openshift-machine-api", "ovirt-credentials")
	if err != nil {
		return "", err
	}
	send, err := c.SystemService().VmsService().List().Search(fmt.Sprintf("name=%s", nodeName)).Send()
	if err != nil {
		r.log.Error(err, "Failed to find VM", "VM name", nodeName)
		return "", err
	}
	vms := send.MustVms().Slice()
	if len(vms) != 1 {
		return "", fmt.Errorf("expected to get 1 VM but got %v", len(vms))
	}
	return vms[0].MustId(), nil
}

func Add(mgr manager.Manager, opts manager.Options) error {
	reconciler, err := NewProviderIDReconciler(mgr)

	if err != nil {
		return fmt.Errorf("error building reconciler: %v", err)
	}

	c, err := controller.New("provdierID-controller", mgr, controller.Options{Reconciler: reconciler})
	if err != nil {
		return err
	}

	//Watch node changes
	err = c.Watch(&source.Kind{Type: &corev1.Node{}}, &handler.EnqueueRequestForObject{})
	if err != nil {
		return err
	}

	return nil
}

func NewProviderIDReconciler(mgr manager.Manager) (*providerIDReconciler, error) {
	log.SetLogger(klogr.New())
	r := providerIDReconciler{
		log:    log.Log.WithName("controllers").WithName("providerID-reconciler"),
		client: mgr.GetClient(),
	}
	r.fetchProviderIDFunc = r.fetchOvirtVmID
	return &r, nil
}

func (r *providerIDReconciler) getConnection(namespace, secretName string) (*ovirtsdk.Connection, error) {
	var err error
	if r.ovirtApi == nil || r.ovirtApi.Test() != nil {
		// session expired or some other error, re-login.
		r.ovirtApi, err = createApiConnection(r.client, namespace, secretName)
	}
	return r.ovirtApi, err
}

//createApiConnection returns a a client to oVirt's API endpoint
func createApiConnection(client client.Client, namespace string, secretName string) (*ovirtsdk.Connection, error) {
	creds, err := clients.GetCredentialsSecret(client, namespace, secretName)

	if err != nil {
		return nil, fmt.Errorf("failed getting credentials for namespace %s, %s", namespace, err)
	}

	connection, err := ovirtsdk.NewConnectionBuilder().
		URL(creds.URL).
		Username(creds.Username).
		Password(creds.Password).
		CAFile(creds.CAFile).
		Insecure(creds.Insecure).
		Build()
	if err != nil {
		return nil, err
	}

	return connection, nil
}
