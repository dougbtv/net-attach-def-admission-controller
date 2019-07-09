#!/bin/bash
NAMESPACE="kube-system"
BASE_DIR=$(cd $(dirname $0)/..; pwd)
kubectl -n ${NAMESPACE} delete -f ${BASE_DIR}/deployments/service.yaml
cat ${BASE_DIR}/deployments/webhook.yaml | \
        ${BASE_DIR}/hack/webhook-patch-ca-bundle.sh | \
        sed -e "s|\${NAMESPACE}|${NAMESPACE}|g" | \
        kubectl -n ${NAMESPACE} delete -f -
kubectl -n ${NAMESPACE} delete -f ${BASE_DIR}/deployments/deployment.yaml
kubectl -n ${NAMESPACE} delete -f ${BASE_DIR}/deployments/rbac.yaml