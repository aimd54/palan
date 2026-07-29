# Copyright The palan Authors
# SPDX-License-Identifier: Apache-2.0
#
# Distroless palan image, primarily the Kubernetes init-container puller
# (see docs/guides/kubernetes.md): `palan pull $MODEL --output /models`
# into an emptyDir.

FROM golang:1.26@sha256:3aff6657219a4d9c14e27fb1d8976c49c29fddb70ba835014f477e1c70636647 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w -X github.com/aimd54/palan/internal/version.version=${VERSION}" \
      -o /out/palan ./cmd/palan

FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35
COPY --from=build /out/palan /usr/local/bin/palan
# The store lives on a mounted volume in pod usage; default it somewhere
# writable for ad-hoc runs.
ENV PALAN_HOME=/tmp/palan
ENTRYPOINT ["/usr/local/bin/palan"]
