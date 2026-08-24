# Copyright The palan Authors
# SPDX-License-Identifier: Apache-2.0
#
# Distroless palan image, primarily the Kubernetes init-container puller
# (see docs/guides/kubernetes.md): `palan pull $MODEL --output /models`
# into an emptyDir.

FROM golang:1.27@sha256:65b6f280bf050ec5af12716857e8ea8439d694dbba8f31ceeb7630670071f2bb AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/aimd54/palan/internal/version.version=${VERSION}" \
      -o /out/palan ./cmd/palan

FROM gcr.io/distroless/static-debian12:nonroot@sha256:1b7b9f0f0e0a1d2155f531db587cc48ec26aaf97ab64364225f5bf18a054e66a
COPY --from=build /out/palan /usr/local/bin/palan
# The store lives on a mounted volume in pod usage; default it somewhere
# writable for ad-hoc runs.
ENV PALAN_HOME=/tmp/palan
ENTRYPOINT ["/usr/local/bin/palan"]
