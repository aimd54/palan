// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package transfer moves model artifacts between OCI registries and the
// local store. It is a thin, registry-agnostic layer over oras-go v2
// (ADR-0005): oras.Copy does graph traversal and tagging, while large leaf
// blobs take a custom download path that survives interruption via HTTP
// Range resume (design §8.1).
package transfer

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"

	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
	"oras.land/oras-go/v2/registry/remote/credentials"
	"oras.land/oras-go/v2/registry/remote/retry"
)

// DefaultConcurrency is the default number of parallel blob streams.
const DefaultConcurrency = 4

// Options configures a transfer Client.
type Options struct {
	// PlainHTTP uses HTTP instead of HTTPS (lab bring-up only).
	PlainHTTP bool
	// InsecureSkipTLSVerify disables TLS certificate verification. The CLI
	// warns loudly when this is set; it is never the default (design §11).
	InsecureSkipTLSVerify bool
	// CAFile adds a PEM CA bundle (e.g. the internal CA) to the trust pool.
	CAFile string
	// Credential overrides credential resolution; nil uses the Docker
	// credentials store (~/.docker/config.json and credential helpers).
	Credential auth.CredentialFunc
	// UserAgent identifies moci to registries.
	UserAgent string
	// Concurrency bounds parallel blob streams; <=0 means DefaultConcurrency.
	Concurrency int
}

// Client performs pulls, pushes, and copies against remote repositories.
type Client struct {
	opts       Options
	authClient *auth.Client
}

// New builds a Client, wiring credentials and TLS options.
func New(opts Options) (*Client, error) {
	if opts.Concurrency <= 0 {
		opts.Concurrency = DefaultConcurrency
	}

	cred := opts.Credential
	if cred == nil {
		store, err := credentials.NewStoreFromDocker(credentials.StoreOptions{})
		if err != nil {
			return nil, fmt.Errorf("opening Docker credentials store: %w", err)
		}
		cred = credentials.Credential(store)
	}

	transport, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, fmt.Errorf("unexpected default transport type")
	}
	transport = transport.Clone()
	if opts.CAFile != "" || opts.InsecureSkipTLSVerify {
		tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if opts.CAFile != "" {
			pem, err := os.ReadFile(opts.CAFile)
			if err != nil {
				return nil, fmt.Errorf("reading CA file: %w", err)
			}
			pool, err := x509.SystemCertPool()
			if err != nil {
				pool = x509.NewCertPool()
			}
			if !pool.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("no certificates found in %s", opts.CAFile)
			}
			tlsCfg.RootCAs = pool
		}
		if opts.InsecureSkipTLSVerify {
			tlsCfg.InsecureSkipVerify = true // #nosec G402 -- explicit, loudly-warned opt-in for lab bring-up (design §11)
		}
		transport.TLSClientConfig = tlsCfg
	}

	authClient := &auth.Client{
		Client:     &http.Client{Transport: retry.NewTransport(transport)},
		Cache:      auth.NewCache(),
		Credential: cred,
	}
	if opts.UserAgent != "" {
		authClient.SetUserAgent(opts.UserAgent)
	}

	return &Client{opts: opts, authClient: authClient}, nil
}

// Repository opens a handle on the repository containing ref.
func (c *Client) Repository(ref registry.Reference) (*remote.Repository, error) {
	repo, err := remote.NewRepository(ref.Registry + "/" + ref.Repository)
	if err != nil {
		return nil, fmt.Errorf("opening repository %s/%s: %w", ref.Registry, ref.Repository, err)
	}
	repo.Client = c.authClient
	repo.PlainHTTP = c.opts.PlainHTTP
	return repo, nil
}

// concurrency returns the effective parallel stream count.
func (c *Client) concurrency() int { return c.opts.Concurrency }

// scheme returns the URL scheme matching the PlainHTTP option.
func (c *Client) scheme() string {
	if c.opts.PlainHTTP {
		return "http"
	}
	return "https"
}
