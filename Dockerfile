# Copyright The palan Authors
# SPDX-License-Identifier: Apache-2.0
#
# Distroless palan image — primarily the Kubernetes init-container puller
# (design §10.1): `palan pull $MODEL --output /models` into an emptyDir.

FROM golang:1.25 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/aimd54/palan/internal/version.version=${VERSION}" \
      -o /out/palan ./cmd/palan

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/palan /usr/local/bin/palan
# The store lives on a mounted volume in pod usage; default it somewhere
# writable for ad-hoc runs.
ENV PALAN_HOME=/tmp/palan
ENTRYPOINT ["/usr/local/bin/palan"]
