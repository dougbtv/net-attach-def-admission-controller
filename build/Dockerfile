# Copyright (c) 2018 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http:#www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM golang:1.12

ENV PKG_NAME=github.com/K8sNetworkPlumbingWG/net-attach-def-admission-controller
ENV PKG_PATH=$GOPATH/src/$PKG_NAME
ENV GO111MODULE=off
WORKDIR $PKG_PATH

COPY . $PKG_PATH/
RUN ./build.sh

CMD ["./bin/webhook"]
