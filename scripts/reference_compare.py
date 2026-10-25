#!/usr/bin/env python3
"""Compare MoonDiag fixtures with independent Python references.

References (dev-only, not runtime dependencies):
  pip install --target D:/Codex/tools/pyrefs can-isotp==2.0.7 udsoncan==1.26.1

Run:
  MOONBIT_PYREFS=D:/Codex/tools/pyrefs python scripts/reference_compare.py
"""
import os
import sys

REFS = os.environ.get("MOONBIT_PYREFS", r"D:\Codex\tools\pyrefs")
sys.path.insert(0, REFS)

import isotp  # noqa: E402
import udsoncan  # noqa: E402
from udsoncan import Response  # noqa: E402
from udsoncan.services import ReadDTCInformation  # noqa: E402

failures = []


def check(name, condition, detail=""):
    status = "PASS" if condition else "FAIL"
    print(f"[{status}] {name} {detail}")
    if not condition:
        failures.append(name)


# 1. ISO-TP reassembly: the same FF/CF frames used by MoonDiag's example.
frames = [
    isotp.CanMessage(0x7E8, 8, bytes.fromhex("101462F190313233")),
    isotp.CanMessage(0x7E8, 8, bytes.fromhex("2134353637383930")),
    isotp.CanMessage(0x7E8, 8, bytes.fromhex("2241424344454647")),
]
sent = []


def rxfn(_timeout):
    return frames.pop(0) if frames else None


def txfn(msg):
    sent.append(msg.data.hex())


address = isotp.Address(
    isotp.AddressingMode.Normal_11bits, txid=0x7E0, rxid=0x7E8
)
tp = isotp.TransportLayer(rxfn, txfn, address)
tp.start()
try:
    payload = tp.recv(block=True, timeout=1)
finally:
    tp.stop()

check(
    "isots reassembly",
    payload is not None
    and payload.hex().upper()
    == "62F1903132333435363738393041424344454647",
    f"payload={payload.hex().upper() if payload else None}",
)

# 2. UDS negative response.
negative = Response.from_payload(bytes.fromhex("7F2231"))
check(
    "uds negative 7F 22 31",
    negative.positive is False
    and negative.code == 0x31
    and negative.service.__name__ == "ReadDataByIdentifier",
    f"positive={negative.positive} code=0x{negative.code:02X}",
)

# 3. UDS DID positive response.
did = Response.from_payload(
    bytes.fromhex("62F1903132333435363738393041424344454647")
)
check(
    "uds DID F190",
    did.positive is True
    and did.service.__name__ == "ReadDataByIdentifier"
    and did.data.hex().upper().startswith("F190"),
    f"service={did.service.__name__} data={did.data.hex().upper()}",
)

# 4. UDS DTC record: 3-byte DTC + 1 status byte.
dtc_response = Response.from_payload(bytes.fromhex("5902FF03012F00"))
interpreted = ReadDTCInformation.interpret_response(
    dtc_response, subfunction=0x02
).service_data
dtc = interpreted.dtcs[0] if interpreted.dtcs else None
check(
    "uds DTC 03 01 2F 00",
    interpreted.dtc_count == 1
    and dtc is not None
    and dtc.id == 0x03012F
    and dtc.status.get_byte_as_int() == 0x00,
    f"count={interpreted.dtc_count} id=0x{dtc.id:06X} "
    f"status=0x{dtc.status.get_byte_as_int():02X}",
)

print(
    f"\nversions: can-isotp {isotp.__version__ if hasattr(isotp, '__version__') else '2.0.7'}, "
    f"udsoncan {getattr(udsoncan, '__version__', '1.26.1')}"
)
if failures:
    print("FAILED:", ", ".join(failures))
    sys.exit(1)
print("All reference comparisons passed.")
