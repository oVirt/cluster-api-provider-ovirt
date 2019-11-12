module github.com/ovirt/cluster-api-provider-ovirt

go 1.12

require (
	github.com/golang/groupcache v0.0.0-20190129154638-5b532d6fd5ef // indirect
	github.com/openshift/cluster-api v0.0.0-20191030113141-9a3a7bbe9258

	github.com/ovirt/go-ovirt v4.3.4+incompatible
	github.com/pkg/errors v0.8.1
	k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	k8s.io/klog v1.0.0
	sigs.k8s.io/controller-runtime v0.2.0
	sigs.k8s.io/controller-tools v0.2.2-0.20190919191502-76a25b63325a
	sigs.k8s.io/yaml v1.1.0
)

replace sigs.k8s.io/controller-runtime => github.com/enxebre/controller-runtime v0.2.0-beta.1.0.20191011155846-b2bc3490f2e3
