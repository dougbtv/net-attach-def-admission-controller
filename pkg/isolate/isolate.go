package isolate

import (
  "fmt"
  // "log"
  "strings"
  // "time"

  // "github.com/cloudflare/cfssl/csr"

  "github.com/golang/glog"
  arv1beta1 "k8s.io/api/admissionregistration/v1beta1"
  // "k8s.io/api/certificates/v1beta1"
  "k8s.io/client-go/kubernetes"
  "k8s.io/client-go/rest"
  // corev1 "k8s.io/api/core/v1"
  metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
  // "k8s.io/apimachinery/pkg/util/intstr"
)

var (
  clientset kubernetes.Interface
  namespace string
  prefix    string
)

// Initialize does the initial setup.
func Initialize() error {

  prefix = "net-attach-def-admission-controller"
  namespace = "kube-system"

  /* setup Kubernetes API client */
  config, err := rest.InClusterConfig()
  if err != nil {
    glog.Fatalf("FATAL: isolate.Initialize error loading Kubernetes in-cluster configuration: %s", err)
    return err
  }

  clientset, err = kubernetes.NewForConfig(config)
  if err != nil {
    glog.Fatalf("FATAL: isolate.Initialize error setting up Kubernetes client: %s", err)
    return err
  }

  // /* get CSR and private key */
  // csr, key, err := generateCSR()
  // if err != nil {
  //   glog.Fatalf("FATAL: error generating CSR and private key: %s", err)
  // }
  // glog.Info("INFO: raw CSR and private key successfully created")

  /* obtain signed certificate */
  certificate, err := getSignedCertificate("net-attach-def-admission-controller-service.kube-system")
  if err != nil {
    glog.Fatalf("FATAL: error getting signed certificate: %s", err)
    return err
  }

  err = createValidatingWebhookConfiguration(certificate)
  if err != nil {
    glog.Fatalf("FATAL: error creating validating webhook configuration: %s", err)
    return err
  }

  glog.Infof("Succeeded in intializing isolate dynamic configuration")
  return nil
}

// func generateCSR() ([]byte, []byte, error) {
//   glog.Info("INFO: generating Certificate Signing Request")
//   serviceName := strings.Join([]string{prefix, "service"}, "-")
//   certRequest := csr.New()
//   certRequest.KeyRequest = &csr.BasicKeyRequest{"rsa", 2048}
//   certRequest.CN = strings.Join([]string{serviceName, namespace, "svc"}, ".")
//   certRequest.Hosts = []string{
//     serviceName,
//     strings.Join([]string{serviceName, namespace}, "."),
//     strings.Join([]string{serviceName, namespace, "svc"}, "."),
//   }
//   return csr.ParseRequest(certRequest)
// }

func getSignedCertificate(csrName string) ([]byte, error) {

  // csrName := strings.Join([]string{prefix, "csr"}, "-")
  csr, err := clientset.CertificatesV1beta1().CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
  if csr != nil && err == nil {
    glog.Infof("INFO: CSR %s has been found", csrName)
    if csr.Status.Certificate != nil {
      glog.Infof("INFO: using already issued certificate for CSR %s", csrName)
      return csr.Status.Certificate, nil
    }
  }

  // /* wait for the cert to be issued */
  // glog.Infof("INFO: waiting for the signed certificate to be issued...")
  // start := time.Now()
  // for range time.Tick(time.Second) {
  //   glog.Infof("Attempt to get signed cert #%v", time.Since(start))
  //   csr, err := clientset.CertificatesV1beta1().CertificateSigningRequests().Get(csrName, metav1.GetOptions{})
  //   if err != nil {
  //     return nil, fmt.Errorf("error getting signed ceritificate from the API server: %s", err)
  //   }
  //   if csr.Status.Certificate != nil {
  //     return csr.Status.Certificate, nil
  //   }
  //   if time.Since(start) > 60*time.Second {
  //     break
  //   }
  // }

  glog.Errorf("CSR named '%s' is not found", csrName)
  return nil, fmt.Errorf("CSR named '%s' is not found", csrName)

  // glog.Infof("INFO: creating CSR %s", csrName)
  // /* build Kubernetes CSR object */
  // csr := &v1beta1.CertificateSigningRequest{}
  // csr.ObjectMeta.Name = csrName
  // csr.ObjectMeta.Namespace = namespace
  // csr.Spec.Request = request
  // csr.Spec.Groups = []string{"system:authenticated"}
  // csr.Spec.Usages = []v1beta1.KeyUsage{v1beta1.UsageDigitalSignature, v1beta1.UsageServerAuth, v1beta1.UsageKeyEncipherment}

  // /* push CSR to Kubernetes API server */
  // csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().Create(csr)
  // if err != nil {
  //   return nil, fmt.Errorf("error creating CSR in Kubernetes API: %s", err)
  // }
  // glog.Infof("INFO: CSR pushed to the Kubernetes API")

  // /* approve certificate in K8s API */
  // csr.ObjectMeta.Name = csrName
  // csr.ObjectMeta.Namespace = namespace
  // csr.Status.Conditions = append(csr.Status.Conditions, v1beta1.CertificateSigningRequestCondition{
  //   Type:           v1beta1.CertificateApproved,
  //   Reason:         "Approved by net-attach-def admission controller installer",
  //   Message:        "This CSR was approved by net-attach-def admission controller installer.",
  //   LastUpdateTime: metav1.Now(),
  // })
  // csr, err = clientset.CertificatesV1beta1().CertificateSigningRequests().UpdateApproval(csr)
  // glog.Infof("INFO: certificate approval sent")
  // if err != nil {
  //   return nil, fmt.Errorf("error approving CSR in Kubernetes API: %s", err)
  // }

  // return nil, fmt.Errorf("error getting certificate from the API server: request timed out - verify that Kubernetes certificate signer is setup, more at https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster/#a-note-to-cluster-administrators")
}

func createValidatingWebhookConfiguration(certificate []byte) error {
  configName := strings.Join([]string{prefix, "isolating-config"}, "-")
  serviceName := strings.Join([]string{prefix, "isolating-service"}, "-")
  removeValidatingWebhookIfExists(configName)
  failurePolicy := arv1beta1.Ignore
  path := "/isolate"
  configuration := &arv1beta1.ValidatingWebhookConfiguration{
    ObjectMeta: metav1.ObjectMeta{
      Name: configName,
      Labels: map[string]string{
        "app": prefix,
      },
    },
    Webhooks: []arv1beta1.Webhook{
      {
        Name: configName + ".k8s.io",
        ClientConfig: arv1beta1.WebhookClientConfig{
          CABundle: certificate,
          Service: &arv1beta1.ServiceReference{
            Namespace: namespace,
            Name:      serviceName,
            Path:      &path,
          },
        },
        FailurePolicy: &failurePolicy,
        Rules: []arv1beta1.RuleWithOperations{
          {
            Operations: []arv1beta1.OperationType{arv1beta1.Create},
            Rule: arv1beta1.Rule{
              APIGroups:   []string{"apps", ""},
              APIVersions: []string{"v1"},
              Resources:   []string{"pods"},
            },
          },
        },
      },
    },
  }

  _, err := clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Create(configuration)
  return err
}

// ClientConfig: arv1beta1.WebhookClientConfig{
//   CABundle: certificate,
//   Service: &arv1beta1.ServiceReference{
//     Namespace: namespace,
//     Name:      serviceName,
//     Path:      &path,
//   },
// },

func removeValidatingWebhookIfExists(configName string) {
  validatingWebhok, err := clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Get(configName, metav1.GetOptions{})
  if validatingWebhok != nil && err == nil {
    glog.Infof("INFO: validating webhook %s already exists, removing it first", configName)
    err := clientset.AdmissionregistrationV1beta1().ValidatingWebhookConfigurations().Delete(configName, &metav1.DeleteOptions{})
    if err != nil {
      fmt.Errorf("error trying to remove validating webhook configuration: %s", err) // ?
    }
    glog.Infof("INFO: validating webhook configuration %s removed", configName)
  }
}

// ---
// apiVersion: admissionregistration.k8s.io/v1beta1
// kind: ValidatingWebhookConfiguration
// metadata:
//   name: net-attach-def-admission-controller-isolating-config
// webhooks:
//   - name: net-attach-def-admission-controller-isolating-config.k8s.io
//     clientConfig:
//       service:
//         name: net-attach-def-admission-controller-service
//         namespace: ${NAMESPACE}
//         path: "/isolate"
//       caBundle: ${CA_BUNDLE}
//     rules:
//       - operations: [ "CREATE" ]
//         apiGroups: ["apps", ""]
//         apiVersions: ["v1"]
//         resources: ["pods"]
