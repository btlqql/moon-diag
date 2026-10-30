# MoonDiag 0.3.0 review evidence

Basic CAN, ISO-TP, UDS and DTC codecs already exist; this project does not use
their existence as a novelty claim. Its independent task is auditing the state
of a recorded UDS conversation across requests and responses, particularly
security access and a firmware-download sequence.

## Complete software task

`scripts/client_replay.py` runs the real udsoncan 1.26.1 Client against an
author-written deterministic software ECU. The client changes session, requests
a seed, sends a key, requests a download, transfers two blocks and exits. Its
requests are emitted by udsoncan and its responses validated by that library.
The exported direction/payload log is then audited by MoonDiag.

```sh
moon run cmd/main --target js -- conversation examples/client/udsoncan-download.log
moon run cmd/main --target js -- conversation examples/client/download-size-mismatch.log
```

The first passes with security level 1 and 8 acknowledged data bytes. The second
changes only RequestDownload memorySize from 8 to 9; locally valid individual
responses still fail the overall TRANSFER_SIZE_MISMATCH check. This is a genuine
software-client integration with a simulated peer, not a real vehicle or flash
controller validation. The replay script requires udsoncan only during development.

## Core mechanisms

- `analyze_uds_exchange` accepts directed payloads without a CAN dependency.
- `analyze_uds_payload_log` reads `>>` request / `<<` response lines.
- CAN logs are partitioned by interface before ISO-TP and ECU state analysis.
- Pending and final responses, service and single-DID echoes, seed/key order,
  positive key confirmation and session changes are tracked.
- Download audit covers negotiated block length, block counter FF->00, exact
  retransmission deduplication, acknowledged bytes and transfer exit.
- Malformed CAN input fails; incomplete ISO-TP is rejected; unsupported UDS SIDs
  produce review rather than a false clean pass.

The output is available through typed APIs and CLI exit status, rather than only
a human-readable dump of decoded fields. CLI fail exits 1 and review exits 0.

## Validation and boundaries

Current code passes 40 MoonBit tests on Windows JS, wasm and wasm-gc and builds
as a dependency in an independent consumer. No native/hardware result is inferred
from these runs. Public CI results are recorded separately by fixed commit.

The default physical ID mapping is 0x7E0..0x7E7 -> +8; arbitrary OEM addressing,
functional broadcasts, CAN FD, DoIP parsing, live flow-control timing and P2
timeouts are not implemented. The payload API can be fed by another transport
but does not itself implement that transport. Download auditing supports
uncompressed, unencrypted DFI=0. It does not verify firmware signatures, run OEM
key algorithms, authorize ECU access or perform a real firmware update.
