// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/hf"
	"github.com/aimd54/palan/internal/omsig"
	"github.com/aimd54/palan/internal/pack"
	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/signing"
	"github.com/aimd54/palan/pkg/modelspec"
)

// omsKey is the --oms-key flag's value. It lives at package scope, rather
// than as a local in newPackCmd like the command's other flags, because
// resolveSources reads it directly: verification happens while resolving
// sources, before pack.Options exists to carry it through.
var omsKey string

func newPackCmd(v *viper.Viper) *cobra.Command {
	var (
		tag       string
		profile   string
		sourceURL string
		license   string
		ctxSize   int
		ngl       int
		originSHA string
		doPush    bool
	)

	cmd := &cobra.Command{
		Use:   "pack PATH... -t REF",
		Short: "Build a ModelPack artifact from GGUF or safetensors weights",
		Example: `  # Pack a local GGUF with its licence and serving defaults
  palan pack qwen3-8b-q4.gguf LICENSE -t llm/qwen3:8b-q4 --ctx 8192 --ngl 99

  # Pack a safetensors model directory for distribution
  palan pack ./Qwen3-8B/ -t llm/qwen3:8b-safetensors --license Apache-2.0

  # Pack straight from Hugging Face, then push
  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4 --push`,
		Long: `Pack reads the weights to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

A model split across parts (model-00001-of-00003.gguf) is packed whole:
naming any part brings its siblings in from the same directory, and a part
that is missing is an error, since one part alone would pack and describe
itself like a complete model and then fail to load.

A safetensors model is published as a directory, so naming the directory
packs it. The shard index (model.safetensors.index.json) states which shards
the model is made of: all of them are packed, along with config.json and any
tokenizer files beside them, and a shard the index names that the directory
does not hold is an error. Naming one shard packs the same set.

That artifact is for distribution and verification. It pushes, pulls, signs,
verifies and travels through an air gap on the same code path a GGUF one
does; serve and run refuse it, because llama.cpp reads GGUF and the artifact
declares what it holds. --license is the only source of a license for it,
since safetensors publishes none, and --ctx and --ngl describe llama.cpp's
command line, so they carry no meaning on it.

A PATH may be a local file or a Hugging Face source,
hf://<org>/<repo>/<file>, which is downloaded first:

  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4

The bytes are checked against the SHA-256 the repository publishes and
refused if they differ; a repository publishes that digest for its
LFS-stored files, so a file served inline, such as config.json, carries
none to check and is packed with its origin unrecorded rather than
invented. Where a digest exists it becomes io.palan.origin.sha256, and the
repository page becomes the source annotation. Split parts and a licence
file in the repository travel with the weights. Naming a safetensors
repository without a file resolves the whole model through its shard
index: the shards it names, config.json, the tokenizer files, and any
documentation files beside them, each held against its own published
digest where the repository publishes one. A GGUF repository named
without a file lists what it publishes instead, since more than one
quantisation usually lives there. Gated repositories read HF_TOKEN.

When --oms-key names a public key, the repository's own signature over the
files it publishes is fetched and checked against it, and every downloaded
file is held against what that signature covers, including a file with no
published digest of its own: a file the signature omits, or one whose
bytes hash to something else, refuses the import before anything is
packed. A key supplied against a repository that publishes no such
signature is refused rather than imported unverified. Since only a Hugging
Face source can carry that signature, --oms-key also refuses a PATH list
holding a local file, whether alone or mixed with a repository, rather
than pack part of the artifact with nothing behind it.

Profiles: "artifact" (raw weight layers; the default), "car" (an OCI image
with one tar layer under models/, for Kubernetes image volumes and KServe
modelcars; tagged REF-car), or "both".`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(tag, v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			if err := ref.ValidateReferenceAsTag(); err != nil {
				return fmt.Errorf("pack requires a tag reference, not a digest: %w", err)
			}
			if profile != "artifact" && profile != "car" && profile != "both" {
				return fmt.Errorf("invalid --profile %q (artifact|car|both)", profile)
			}

			files, fetched, err := resolveSources(ctx, cmd, args)
			// Registered ahead of the error check: a refused import can
			// still have created the temp directory and downloaded bytes
			// into it, and those must not outlive the failed command.
			if fetched.tempDir != "" {
				defer func() { _ = os.RemoveAll(fetched.tempDir) }()
			}
			if err != nil {
				return err
			}

			// What the source published beats what palan can infer: the
			// upstream digest is the point of the annotation, and the
			// repository page is a better provenance link than nothing.
			if sourceURL == "" {
				sourceURL = fetched.sourceURL
			}
			if originSHA == "" {
				originSHA = fetched.originSHA256
			}
			opts := pack.Options{
				SourceURL:    sourceURL,
				License:      license,
				OriginSHA256: originSHA,
				Signer:       fetched.signer,
			}
			if ctxSize > 0 || ngl > 0 {
				opts.ServeDefaults = &modelspec.ServeDefaults{Ctx: ctxSize, NGL: ngl}
			}

			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			type packed struct {
				ref  string
				desc ocispec.Descriptor
			}
			var results []packed

			if profile == "artifact" || profile == "both" {
				desc, err := pack.Model(ctx, st, files, ref.String(), opts)
				if err != nil {
					return err
				}
				results = append(results, packed{ref.String(), desc})
			}
			if profile == "car" || profile == "both" {
				carRef := ref
				carRef.Reference = ref.Reference + "-car"
				desc, err := pack.Car(ctx, st, files, carRef.String(), opts)
				if err != nil {
					return err
				}
				results = append(results, packed{carRef.String(), desc})
			}

			for _, r := range results {
				fmt.Fprintf(cmd.OutOrStdout(), "Packed %s\nDigest: %s\n", r.ref, r.desc.Digest)
			}

			if doPush {
				client, err := newTransferClient(v)
				if err != nil {
					return err
				}
				for _, r := range results {
					pushRef, err := refname.Parse(r.ref, "")
					if err != nil {
						return err
					}
					pr := newProgress(v.GetBool("quiet"))
					_, err = client.Push(ctx, st, pushRef, pr.events())
					pr.close(err)
					if err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "Pushed %s\n", r.ref)
				}
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&tag, "tag", "t", "", "reference to tag the packed model with (required)")
	cmd.Flags().StringVar(&profile, "profile", "artifact", "output profile: artifact|car|both")
	cmd.Flags().StringVar(&sourceURL, "source", "", "upstream source URL (org.opencontainers.image.source)")
	cmd.Flags().StringVar(&license, "license", "", "SPDX license expression (default: the GGUF header's general.license; safetensors publishes none)")
	cmd.Flags().IntVar(&ctxSize, "ctx", 0, "default context size for serving (io.palan.serve.defaults)")
	cmd.Flags().IntVar(&ngl, "ngl", 0, "default GPU layer count for serving; unset means serve passes no --n-gpu-layers (io.palan.serve.defaults)")
	cmd.Flags().StringVar(&originSHA, "origin-sha256", "", "SHA-256 of the original upstream file (default: the weight digest)")
	cmd.Flags().StringVar(&omsKey, "oms-key", "", "public key (PEM) that must have signed the source repository's own file digests")
	cmd.Flags().BoolVar(&doPush, "push", false, "push to the registry after packing")
	must(cmd.MarkFlagRequired("tag"))
	return cmd
}

// fetchedSources records what a remote source contributed beyond its files:
// provenance that palan could not otherwise know.
type fetchedSources struct {
	tempDir      string
	sourceURL    string
	originSHA256 string
	// signer identifies the key that verified the source repository's
	// signature over its own file digests (sha256:<hex> of the public
	// key), recorded as io.palan.origin.signer. Empty when --oms-key was
	// not given, so no such signature was checked.
	signer string
}

// resolveSources turns pack arguments into pack.File inputs, downloading any
// hf:// references first. Local paths pass through untouched, so a command can
// mix a fetched model with a licence or template already on disk.
//
// Each fetched file carries the digest the repository published for it,
// where the repository publishes one: an LFS-stored file carries a
// SHA-256, but a file served inline, such as config.json, carries none,
// and none is invented for it. The named weight file's digest and the
// repository URL are also carried back in fetchedSources, because a model
// fetched from a known source should say so rather than annotating itself
// with its own digest.
//
// A supplied verification key can only be honoured for files a repository
// published a signature over: a local path carries no such signature, and
// packing one anyway, whether alone or mixed with a repository, would either
// silently skip verification or annotate the whole artifact as vouched-for
// when part of it never was. Both are worse than refusing, so this checks
// every argument against the key before resolving or downloading any of
// them.
func resolveSources(ctx context.Context, cmd *cobra.Command, args []string) ([]pack.File, fetchedSources, error) {
	var info fetchedSources
	if omsKey != "" {
		for _, a := range args {
			if !hf.IsRef(a) {
				return nil, info, fmt.Errorf(
					"--oms-key was given and %q is not a Hugging Face source: a supplied key can only be honoured for files a repository published a signature over, and a local file is not one of those",
					a)
			}
		}
	}
	if !slices.ContainsFunc(args, hf.IsRef) {
		out := make([]pack.File, 0, len(args))
		for _, a := range args {
			out = append(out, pack.File{Path: a})
		}
		return out, info, nil
	}

	tmp, err := os.MkdirTemp("", "palan-fetch-*")
	if err != nil {
		return nil, info, err
	}
	info.tempDir = tmp
	client := hf.NewClient()
	out := make([]pack.File, 0, len(args))

	for i, arg := range args {
		if !hf.IsRef(arg) {
			out = append(out, pack.File{Path: arg})
			continue
		}
		ref, err := hf.ParseRef(arg)
		if err != nil {
			return nil, info, err
		}
		res, err := client.Resolve(ctx, ref)
		if err != nil {
			return nil, info, err
		}
		// Each reference downloads into a subdirectory of its own, indexed
		// rather than named after the repository, so two references can
		// never share a destination path: a file that lands under the wrong
		// directory would still carry its own repository's published
		// digest, annotating the artifact with bytes its publisher never
		// released.
		srcDir := filepath.Join(tmp, strconv.Itoa(i))
		if err := os.MkdirAll(srcDir, 0o750); err != nil {
			return nil, info, err
		}
		if info.sourceURL == "" {
			info.sourceURL = ref.URL()
		}

		// A key was supplied, so every file this loop downloads must be
		// held against what the repository's own signature covers. The
		// signature is fetched now, before anything downloads, so an
		// unsigned repository is refused up front rather than after
		// spending the transfer.
		var stmt *omsig.Statement
		if omsKey != "" {
			pem, err := os.ReadFile(omsKey) // #nosec G304 -- operator-supplied key path
			if err != nil {
				return nil, info, fmt.Errorf("reading the verification key: %w", err)
			}
			v, err := signing.LoadVerifier(pem)
			if err != nil {
				return nil, info, err
			}
			sig, err := client.FetchSmall(ctx, ref, omsig.FileName)
			switch {
			case errors.Is(err, hf.ErrFileNotFound):
				// The only failure that actually means "unsigned": the
				// repository was reachable and simply has no model.sig.
				return nil, info, fmt.Errorf(
					"a verification key was given and %s publishes no %s to check against it",
					ref.Repo, omsig.FileName)
			case err != nil:
				// Anything else, gated, rate limited, offline, is a fetch
				// failure, not evidence the repository is unsigned; let it
				// speak for itself rather than push an operator toward
				// dropping the key over a transient problem.
				return nil, info, fmt.Errorf("fetching %s to check against the supplied key: %w", omsig.FileName, err)
			}
			stmt, err = omsig.Verify(sig, v)
			if err != nil {
				return nil, info, fmt.Errorf("%s: %w", ref.Repo, err)
			}
			info.signer = stmt.KeyID
		}

		for _, f := range res.Files {
			fmt.Fprintf(cmd.ErrOrStderr(), "Fetching %s (%s)\n", f.Path, humanBytes(f.Size))
			path, err := client.Download(ctx, ref, res.Revision, f, srcDir, hf.Events{})
			if err != nil {
				return nil, info, err
			}
			// Held against the digest of the bytes that landed on disk,
			// not the digest the API advertised: that digest is what
			// Download already checked the transfer against, so
			// comparing it to the signature would check the API against
			// itself and prove nothing about what was written. The
			// signature file names itself among the repository's files
			// in some layouts; a statement never covers itself, so it is
			// the one path this check skips, by exact name, rather than
			// by any broader rule.
			if stmt != nil && f.Path != omsig.FileName {
				sum, err := fileSHA256(path)
				if err != nil {
					return nil, info, err
				}
				if err := stmt.Covers(f.Path, sum); err != nil {
					return nil, info, fmt.Errorf("%s: %w", ref.Repo, err)
				}
			}
			// The named weight file is the one whose provenance the
			// manifest states; a licence fetched alongside it is not
			// what the artifact is.
			if f.Path == ref.Path && f.SHA256 != "" {
				info.originSHA256 = "sha256:" + f.SHA256
			}
			out = append(out, pack.File{
				Path:           path,
				Name:           filepath.Base(f.Path),
				OriginSHA256:   f.SHA256,
				SourceRepo:     sourceRepo(client, ref),
				SourcePath:     f.Path,
				SourceRevision: res.Revision,
			})
		}
	}
	return out, info, nil
}

// sourceRepo names a repository the way a reader outside palan would: the
// host that served it and the path on it, rather than the hf:// scheme that
// only means something here.
func sourceRepo(c *hf.Client, ref hf.Ref) string {
	host := strings.TrimPrefix(strings.TrimPrefix(c.Endpoint, "https://"), "http://")
	if host == "" {
		host = "huggingface.co"
	}
	return host + "/" + ref.Repo
}

// fileSHA256 hashes a downloaded file so it can be checked against what the
// publisher's signature covers.
func fileSHA256(path string) (string, error) {
	fh, err := os.Open(path) // #nosec G304 -- path was written by this process
	if err != nil {
		return "", err
	}
	defer func() { _ = fh.Close() }()
	h := sha256.New()
	if _, err := io.Copy(h, fh); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
