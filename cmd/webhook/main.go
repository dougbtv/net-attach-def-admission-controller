// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"flag"
	"fmt"
	"net/http"

	"github.com/K8sNetworkPlumbingWG/net-attach-def-admission-controller/pkg/isolate"
	"github.com/K8sNetworkPlumbingWG/net-attach-def-admission-controller/pkg/webhook"
	"github.com/golang/glog"
)

func main() {
	/* load configuration */
	port := flag.Int("port", 443, "The port on which to serve.")
	address := flag.String("bind-address", "0.0.0.0", "The IP address on which to listen for the --port port.")
	cert := flag.String("tls-cert-file", "cert.pem", "File containing the default x509 Certificate for HTTPS.")
	key := flag.String("tls-private-key-file", "key.pem", "File containing the default x509 private key matching --tls-cert-file.")
	flag.Parse()

	glog.Infof("starting net-attach-def-admission-controller webhook server")

	/* init API client */
	webhook.SetupInClusterClient()

	// init the isolate
	err := isolate.Initialize()
	if err != nil {
		glog.Fatalf("error initializing dynamic isolation webhook configuration routines: %s", err.Error())

	}

	/* register handlers */
	http.HandleFunc("/validate", webhook.ValidateHandler)
	http.HandleFunc("/isolate", webhook.IsolateHandler)

	/* start serving */
	err = http.ListenAndServeTLS(fmt.Sprintf("%s:%d", *address, *port), *cert, *key, nil)
	if err != nil {
		glog.Fatalf("error starting web server: %s", err.Error())
	}
}
