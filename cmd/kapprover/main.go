package main

import (
	"flag"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/proofpoint/kapprover/inspectors"
	"github.com/proofpoint/kapprover/kapprover"
	log "github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"net/http"
	"strconv"
	"time"

	_ "github.com/proofpoint/kapprover/inspectors/altnamesforpod"
	_ "github.com/proofpoint/kapprover/inspectors/group"
	_ "github.com/proofpoint/kapprover/inspectors/keyusage"
	_ "github.com/proofpoint/kapprover/inspectors/minrsakeysize"
	_ "github.com/proofpoint/kapprover/inspectors/noextensions"
	_ "github.com/proofpoint/kapprover/inspectors/signaturealgorithm"
	_ "github.com/proofpoint/kapprover/inspectors/subjectispodforuser"
	_ "github.com/proofpoint/kapprover/inspectors/username"
)

var (
	kubeconfigPath = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	deleteAfter    = flag.Duration("delete-after", time.Minute, "duration after which to delete filtered requests")
	filters        inspectors.Inspectors
	deniers        inspectors.Inspectors
	warners        inspectors.Inspectors
	metricsPort    = 8081
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

	go serveMetrics(metricsPort)
	kapprover.HandleRequests(filters, deniers, warners, *deleteAfter, client)
}

func serveMetrics(port int) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
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
