"""
BRC-104 core: pure HTTP transport logic, no framework dependencies.

This subpackage contains everything needed to implement BRC-104 over
HTTP without depending on any web framework. Framework adapters in
`bsv_brc.brc104.adapters` translate their framework's request/response
objects into the primitives exposed here.
"""
