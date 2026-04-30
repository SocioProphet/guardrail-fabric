# Release Dry Run

`guardrail-fabric` supports a development release dry-run path.

## Command

```bash
make release-dry-run
```

The command emits:

- `dist/guardrail-fabric.release-dry-run.json`
- `dist/guardrail-fabric.release-dry-run.sha256`

## Current status

This is a local development artifact path. It does not publish a production release and does not update a stable Homebrew artifact formula.

## Promotion requirements

A stable formula path requires:

- versioned GitHub Release;
- immutable artifact URL;
- sha256 checksum;
- SBOM;
- provenance metadata;
- formula tests.

Until those exist, `homebrew-prophet` should keep `guardrail-fabric` as a source-built development formula.
