## palan

Distribute and serve GGUF models as OCI artifacts

### Synopsis

palan pulls, pushes, packs, and serves GGUF models as CNCF ModelPack artifacts
against any OCI 1.1 registry — daemonless, in one binary.

### Options

```
      --ca-file string             PEM CA bundle to trust in addition to the system pool
      --concurrency int            parallel blob streams for transfers (default 4)
      --config string              config file (default ~/.config/palan/config.yaml)
  -h, --help                       help for palan
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan cp](palan_cp.md)	 - Copy a model between registries
* [palan gc](palan_gc.md)	 - Reclaim disk space from unreferenced blobs
* [palan load](palan_load.md)	 - Import models from a tar bundle
* [palan login](palan_login.md)	 - Log in to a registry
* [palan logout](palan_logout.md)	 - Remove stored credentials for a registry
* [palan ls](palan_ls.md)	 - List models in the local store or a remote registry
* [palan pack](palan_pack.md)	 - Build a ModelPack artifact from GGUF and companion files
* [palan pull](palan_pull.md)	 - Pull a model from a registry into the local store
* [palan push](palan_push.md)	 - Push a locally-stored model to its registry
* [palan rm](palan_rm.md)	 - Unlink model references from the local store
* [palan run](palan_run.md)	 - Run a model interactively (pulling it if needed)
* [palan runtime](palan_runtime.md)	 - Manage inference runtimes distributed as OCI artifacts
* [palan save](palan_save.md)	 - Export models to a tar bundle for offline transfer
* [palan serve](palan_serve.md)	 - Serve local models behind one OpenAI-compatible endpoint
* [palan sign](palan_sign.md)	 - Sign a pushed model with a cosign-compatible key
* [palan verify](palan_verify.md)	 - Verify a model's signature against a public key
* [palan version](palan_version.md)	 - Print version information

