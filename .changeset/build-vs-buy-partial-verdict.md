---
"@toiroakr/argent": minor
---

Build-vs-Buy now judges the package's own code and each direct dependency's actual weight separately, instead of blending them into one transitive-dependency-count threshold. A thin wrapper with only one or two heavy direct dependencies now gets a new **PARTIAL** verdict — reimplement the wrapper yourself, keep depending directly on the named heavy dependency(ies) — instead of being lumped into REIMPLEMENT?/CONSIDER/KEEP. Each direct dependency's exclusive install footprint is now shown as its own finding row.
