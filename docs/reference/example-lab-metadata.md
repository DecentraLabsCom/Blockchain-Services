# Example lab metadata

This is illustrative NFT/lab metadata for documentation and fixtures. URLs, dates and availability values are examples; they are not a live catalogue or an authorization source.

The top-level object follows the common `name`, `description`, `image` and `attributes` shape. Attribute values are intentionally heterogeneous: strings, arrays, numbers and objects are all valid for the consumer that renders lab metadata. `opens`, `closes` and `unavailableWindows.*` use Unix seconds; `timezone` controls the interpretation of the human-readable hours.

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
