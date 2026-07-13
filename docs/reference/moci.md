## moci

Distribute and serve GGUF models as OCI artifacts

### Synopsis

moci pulls, pushes, packs, and serves GGUF models as CNCF ModelPack artifacts
against any OCI 1.1 registry — daemonless, in one binary.

### Options

```
      --ca-file string             PEM CA bundle to trust in addition to the system pool
      --concurrency int            parallel blob streams for transfers (default 4)
      --config string              config file (default ~/.config/moci/config.yaml)
  -h, --help                       help for moci
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [moci cp](moci_cp.md)	 - Copy a model between registries
* [moci gc](moci_gc.md)	 - Reclaim disk space from unreferenced blobs
* [moci load](moci_load.md)	 - Import models from a tar bundle
* [moci login](moci_login.md)	 - Log in to a registry
* [moci logout](moci_logout.md)	 - Remove stored credentials for a registry
* [moci ls](moci_ls.md)	 - List models in the local store or a remote registry
* [moci pack](moci_pack.md)	 - Build a ModelPack artifact from GGUF and companion files
* [moci pull](moci_pull.md)	 - Pull a model from a registry into the local store
* [moci push](moci_push.md)	 - Push a locally-stored model to its registry
* [moci rm](moci_rm.md)	 - Unlink model references from the local store
* [moci run](moci_run.md)	 - Run a model interactively (pulling it if needed)
* [moci runtime](moci_runtime.md)	 - Manage inference runtimes distributed as OCI artifacts
* [moci save](moci_save.md)	 - Export models to a tar bundle for offline transfer
* [moci serve](moci_serve.md)	 - Serve local models behind one OpenAI-compatible endpoint
* [moci sign](moci_sign.md)	 - Sign a pushed model with a cosign-compatible key
* [moci verify](moci_verify.md)	 - Verify a model's signature against a public key
* [moci version](moci_version.md)	 - Print version information

