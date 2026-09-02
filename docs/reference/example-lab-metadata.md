# Example lab metadata

This is illustrative NFT/lab metadata for documentation and fixtures. URLs, dates and availability values are examples; they are not a live catalogue or an authorization source.

When this document is fetched by `blockchain-services`, the `tokenURI` must
be an HTTPS URL whose origin is registered for the provider on-chain. The
backend does not fetch arbitrary `http://`, `ipfs://` or filesystem targets.

For the gateway's full lab-administration setup, `name` and `description` are
required top-level fields. Top-level `image`, `images` and `docs` values, when
present, must be HTTPS or gateway content URLs. The `attributes` array below is
consumer metadata; it does not bypass the on-chain lab configuration or access
validation. See [Lab administration and content](../services/lab-administration/LAB_ADMINISTRATION.md)
for publishing and content-retention behavior.

The top-level object follows the common `name`, `description`, `image` and
`attributes` shape. Attribute values are intentionally heterogeneous: strings,
arrays, numbers and objects are all valid for the consumer that renders lab
metadata. `opens`, `closes` and `unavailableWindows.*` use Unix seconds;
`timezone` controls the interpretation of the human-readable hours.

```json
{
  "name": "Basic Electronics Lab",
  "description": "Design circuits with an easy-to-use schematic editor. Test Ohm's law and power dissipation concepts through guided experiments.",
  "image": "https://sarlab.dia.uned.es/labs/imgs/lab1-1.png",
  "attributes": [
    { "trait_type": "category", "value": "electronics" },
    { "trait_type": "keywords", "value": ["Ohm's Law", "Power Dissipation", "Kirchhoff's Laws", "Series/Parallel Resistors"] },
    { "trait_type": "docs", "value": ["https://sarlab.dia.uned.es/labs/docs/lab1-1.pdf", "https://sarlab.dia.uned.es/labs/docs/lab1-2.pdf"] },
    { "trait_type": "additionalImages", "value": ["https://sarlab.dia.uned.es/labs/imgs/lab1-2.png", "https://sarlab.dia.uned.es/labs/imgs/lab1-3.png"] },
    { "trait_type": "timeSlots", "value": [30, 60] },
    { "trait_type": "opens", "value": 1749945600 },
    { "trait_type": "closes", "value": 1767139200 },
    { "trait_type": "availableDays", "value": ["MONDAY", "TUESDAY", "WEDNESDAY", "THURSDAY", "FRIDAY"] },
    { "trait_type": "availableHours", "value": { "start": "08:00", "end": "18:00" } },
    { "trait_type": "timezone", "value": "Europe/Madrid" },
    { "trait_type": "maxConcurrentUsers", "value": 5 },
    { "trait_type": "unavailableWindows", "value": [
      { "startUnix": 1751587200, "endUnix": 1751846399, "reason": "Independence Day festivity" },
      { "startUnix": 1755244800, "endUnix": 1755259200, "reason": "Calibration window" },
      { "startUnix": 1766577600, "endUnix": 1766750400, "reason": "Holiday freeze" }
    ] }
  ]
}
```

### Accepted aliases and normalization

The generated-metadata publisher accepts both the common root aliases and the
consumer-oriented attributes. It normalizes them before writing
`metadata.json`:

- `image` is the first image. If it is absent or blank, the first item from root
  `images` or `attributes.additionalImages` becomes the primary image.
- Root `images` and `attributes.additionalImages` are merged in that order,
  duplicates are removed, and the remaining items are stored as the
  `additionalImages` attribute.
- Root `docs` and `attributes.docs` are merged with duplicates removed and are
  stored as the `docs` attribute.
- Root `periodRules` is copied to the `periodRules` attribute only when that
  attribute is not already present.
- The root aliases `images`, `docs` and `periodRules` are removed from the
  generated file after normalization. The original input is not an
  authorization source.

For example, this input is valid and is normalized to one primary image plus
one additional image and one deduplicated documentation list:

```json
{
  "name": "Alias example",
  "description": "Shows the accepted root aliases.",
  "images": [
    "https://provider.example/labs/primary.png",
    "https://provider.example/labs/secondary.png"
  ],
  "docs": ["https://provider.example/labs/guide.pdf"],
  "attributes": [
    { "trait_type": "additionalImages", "value": ["https://provider.example/labs/secondary.png"] },
    { "trait_type": "docs", "value": ["https://provider.example/labs/guide.pdf", "https://provider.example/labs/safety.pdf"] }
  ]
}
```
