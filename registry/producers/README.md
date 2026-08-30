# Producer registry

Each admitted issuer has one public registry file named `<issuer>.json`.

Example:

```json
{
  "issuer": "p_example",
  "keys": {
    "k1": "BASE64URL_ED25519_PUBLIC_KEY_WITHOUT_PADDING"
  },
  "grants": [
    {
      "kind": "probe.requested.v1",
      "targets": ["t_example"]
    }
  ]
}
```

Registry identities are public and should be opaque. Private signing keys never belong in this repository.
