# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

FROM registry.svc.ci.openshift.org/openshift/release:golang-1.13 AS builder

ARG version 
ARG release 

LABEL   com.redhat.component="machine-api" \
        name="cluster-api-provider-ovirt" \
        version="$version" \
        release="$release" \
        architecture="x86_64" \
        summary="cluster-api-provider-ovirt" \
        maintainer="Roy Golan <rgolan@redhat.com>"

WORKDIR /go/cluster-api-provider-ovirt
COPY . .


RUN git --version 
RUN make build

FROM registry.access.redhat.com/ubi8/ubi-minimal

COPY --from=builder /go/cluster-api-provider-ovirt/bin/manager /
COPY --from=builder /go/cluster-api-provider-ovirt/bin/machine-controller-manager /
