package kapprover

import (
	"context"
	"fmt"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/proofpoint/kapprover/inspectors"
	log "github.com/sirupsen/logrus"
	certificates "k8s.io/api/certificates/v1beta1"
	"k8s.io/api/core/v1"
	metaV1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	scheduled    = map[string]bool{}
	scheduledMux sync.Mutex
)

var (
	requestsApproved = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kapprover_requests_approved",
			Help: "Number of approved requests.",
		},
		[]string{},
	)
	requestsDenied = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kapprover_requests_denied",
			Help: "Number of denied requests.",
		},
		[]string{"reason"},
	)
	requestsWarned = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kapprover_requests_warned",
			Help: "Number of warnings on approved requests.",
		},
		[]string{"reason"},
	)
	requestsFiltered = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kapprover_requests_filtered",
			Help: "Number of filtered requests.",
		},
		[]string{"reason"},
	)
	requestsError = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "kapprover_requests_error",
			Help: "Number of requests encountering an error.",
		},
		[]string{"reason"},
	)
)

func registerPrometheusMetrics() {
	prometheus.MustRegister(requestsApproved)
	prometheus.MustRegister(requestsDenied)
	prometheus.MustRegister(requestsWarned)
	prometheus.MustRegister(requestsFiltered)
	prometheus.MustRegister(requestsError)
}

func ServePrometheusMetrics(port int) {
	http.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	http.Handle("/metrics", promhttp.Handler())

	log.Fatal(http.ListenAndServe(":"+strconv.Itoa(port), nil))
}

func HandleRequests(filters inspectors.Inspectors, deniers inspectors.Inspectors, warners inspectors.Inspectors, deleteAfter time.Duration, client *kubernetes.Clientset) {
	//Register prometheus metrics
	registerPrometheusMetrics()

	// Create a watcher and an informer for CertificateSigningRequests.
	// The Add function
	watchList := cache.NewListWatchFromClient(
		client.CertificatesV1beta1().RESTClient(),
		"certificatesigningrequests",
		v1.NamespaceAll,
		fields.Everything(),
	)

	f := func(obj interface{}) {
		if req, ok := obj.(*certificates.CertificateSigningRequest); ok {
			if err := tryApprove(filters, deniers, warners, deleteAfter, client, req); err != nil {
				log.Errorf("Failed to handle %q from %q: %s", req.ObjectMeta.Name, req.Spec.Username, err)
				return
			}
		}
	}

	_, controller := cache.NewInformer(
		watchList,
		&certificates.CertificateSigningRequest{},
		time.Second*30,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				f(obj)
			},
			UpdateFunc: func(_, obj interface{}) {
				f(obj)
			},
		},
	)

	controller.Run(make(chan struct{}))
}

func tryApprove(filters inspectors.Inspectors, deniers inspectors.Inspectors, warners inspectors.Inspectors, deleteAfter time.Duration, client *kubernetes.Clientset, request *certificates.CertificateSigningRequest) error {
	for {
		// Verify that the CSR hasn't been approved or denied already.
		//
		// There are only two possible conditions (CertificateApproved and
		// CertificateDenied). Therefore if the CSR already has a condition,
		// it means that the request has already been approved or denied, and that
		// we should schedule deletion of the request.
		if len(request.Status.Conditions) > 0 {
			scheduleDelete(deleteAfter, client, request.Name)
			return nil
		}

		for _, filter := range filters {
			message, err := filter.Inspector.Inspect(client, request)
			if err != nil {
				requestsError.WithLabelValues(filter.Name).Inc()
				return err
			}
			if message != "" {
				log.Infof("Skipping %q from %q: %s", request.Name, request.Spec.Username, message)
				requestsFiltered.WithLabelValues(filter.Name).Inc()
				return nil
			}
		}

		condition := certificates.CertificateSigningRequestCondition{
			Type:    certificates.CertificateApproved,
			Reason:  "AutoApproved",
			Message: "Approved by kapprover",
		}

		for _, denier := range deniers {
			message, err := denier.Inspector.Inspect(client, request)
			if err != nil {
				requestsError.WithLabelValues(denier.Name).Inc()
				return err
			}
			if message != "" {
				condition.Type = certificates.CertificateDenied
				condition.Reason = denier.Name
				condition.Message = message
				requestsDenied.WithLabelValues(condition.Reason).Inc()
				break
			}
		}

		if condition.Type == certificates.CertificateApproved {
			for _, warner := range warners {
				message, _ := warner.Inspector.Inspect(client, request)
				if message != "" {
					log.Warnf("Approving CSR %q from %q despite %s: %s", request.Name, request.Spec.Username, warner.Name, message)
					requestsWarned.WithLabelValues(warner.Name).Inc()
				}
			}
		}

		request.Status.Conditions = append(request.Status.Conditions, condition)

		// Submit the updated CSR.
		signingRequestInterface := client.CertificatesV1beta1().CertificateSigningRequests()
		if _, err := signingRequestInterface.UpdateApproval(context.TODO(), request, metaV1.UpdateOptions{}); err != nil {
			if strings.Contains(err.Error(), "the object has been modified") {
				// The CSR might have been updated by a third-party, retry until we
				// succeed.
				request, err = signingRequestInterface.Get(context.TODO(), request.ObjectMeta.Name, metaV1.GetOptions{})
				if err != nil {
					return err
				}
				continue
			}
			requestsError.WithLabelValues("updateApproval").Inc()
			return err
		}

		detail := ""
		if condition.Type == certificates.CertificateDenied {
			detail = fmt.Sprintf(" by %s with %q", condition.Reason, condition.Message)
		}

		log.Infof("Successfully %s %q from %q%s", condition.Type, request.ObjectMeta.Name, request.Spec.Username, detail)

		scheduleDelete(deleteAfter, client, request.Name)
		requestsApproved.WithLabelValues().Inc()

		return nil
	}
}

func scheduleDelete(deleteAfter time.Duration, client *kubernetes.Clientset, requestName string) {
	{
		scheduledMux.Lock()
		defer scheduledMux.Unlock()

		if scheduled[requestName] {
			return
		}
		scheduled[requestName] = true
	}

	time.AfterFunc(deleteAfter, func() {
		err := client.CertificatesV1beta1().CertificateSigningRequests().Delete(context.TODO(), requestName, metaV1.DeleteOptions{})
		if err == nil {
			log.Infof("Deleted request %q", requestName)
		} else {
			log.Errorf("Failed to delete request %q: %s", requestName, err)
		}

		scheduledMux.Lock()
		delete(scheduled, requestName)
		scheduledMux.Unlock()
	})
}
