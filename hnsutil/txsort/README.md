# txsort

Package `txsort` provides deterministic ordering for Handshake transaction
inputs and outputs.

Inputs are sorted by transaction hash and output index. Outputs are sorted by
value, then by the serialized Handshake address, and finally by the serialized
covenant. This makes independently assembled transactions reproducible without
discarding Handshake-native output fields.

The package is licensed under the ISC License.
