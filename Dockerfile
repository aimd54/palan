# Copyright The moci Authors
# SPDX-License-Identifier: Apache-2.0
#
# Distroless moci image — primarily the Kubernetes init-container puller
# (design §10.1): `moci pull $MODEL --output /models` into an emptyDir.

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/aimd54/moci/internal/version.version=${VERSION}" \
      -o /out/moci ./cmd/moci

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/moci /usr/local/bin/moci
# The store lives on a mounted volume in pod usage; default it somewhere
# writable for ad-hoc runs.
ENV MOCI_HOME=/tmp/moci
ENTRYPOINT ["/usr/local/bin/moci"]
