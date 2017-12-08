package main

import (
	"flag"
	"time"

	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/proofpoint/kapprover/pkg/inspectors"
	"github.com/proofpoint/kapprover/pkg/kapprover"

	_ "github.com/proofpoint/kapprover/pkg/inspectors/altnamesforpod"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/group"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/keyusage"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/minrsakeysize"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/noextensions"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/signaturealgorithm"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/subjectispodforuser"
	_ "github.com/proofpoint/kapprover/pkg/inspectors/username"
)

var (
	kubeconfigPath = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	deleteAfter    = flag.Duration("delete-after", time.Minute, "duration after which to delete filtered requests")
	filters        inspectors.Inspectors
	deniers        inspectors.Inspectors
	warners        inspectors.Inspectors
)

func init() {
	flag.Var(&filters, "filter", "additional inspector to filter the set of requests to handle")
	flag.Var(&deniers, "denier", "additional inspector to deny requests")
	flag.Var(&warners, "warner", "additional inspector to log warnings (but not block approval)")
}

func main() {
	flag.Parse()

	// Create a Kubernetes client.
	client, err := newClient(*kubeconfigPath)
	if err != nil {
		log.Errorf("Could not create Kubernetes client: %s", err)
		return
	}

	kapprover.HandleRequests(filters, deniers, warners, *deleteAfter, client)
}

func newClient(kubeconfigPath string) (*kubernetes.Clientset, error) {
	var config *rest.Config
	var err error
	if kubeconfigPath != "" {
		// Initialize a configuration from the provided kubeconfig.
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
		if err != nil {
			panic(err.Error())
		}
	} else {
		// Initialize a configuration based on the default service account.
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}

	return kubernetes.NewForConfig(config)
}
