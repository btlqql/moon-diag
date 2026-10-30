"""Run the real udsoncan Client against a deterministic software ECU.

The simulator is a test peer, not a real vehicle. Requests, validation and
conversation sequencing are emitted by udsoncan 1.26.1, not by MoonDiag.
"""
from pathlib import Path
import json
import udsoncan
from udsoncan.client import Client
from udsoncan.connections import BaseConnection
from udsoncan import MemoryLocation
from udsoncan.exceptions import TimeoutException

class SoftwareEcu(BaseConnection):
    def __init__(self):
        super().__init__('moon-diag-reference')
        self.active = False
        self.responses = []
        self.log = []
    def open(self): self.active = True; return self
    def close(self): self.active = False
    def is_open(self): return self.active
    def empty_rxqueue(self): self.responses.clear()
    def specific_send(self, payload, timeout=None):
        payload = bytes(payload)
        self.log.append('>> '+payload.hex(' ').upper())
        if payload[0] == 0x10: answer = bytes.fromhex('50 03 00 32 01 F4')
        elif payload[0] == 0x27 and payload[1] == 1: answer = bytes.fromhex('67 01 11 22')
        elif payload[0] == 0x27 and payload[1] == 2: answer = bytes.fromhex('67 02')
        elif payload[0] == 0x34: answer = bytes.fromhex('74 10 06')
        elif payload[0] == 0x36: answer = bytes([0x76,payload[1]])
        elif payload[0] == 0x37: answer = b'\x77'
        else: answer = bytes([0x7f,payload[0],0x11])
        self.responses.append(answer)
    def specific_wait_frame(self, timeout=None):
        if not self.responses: raise TimeoutException('software ECU has no pending response')
        answer = self.responses.pop(0)
        self.log.append('<< '+answer.hex(' ').upper())
        return answer

peer = SoftwareEcu()
with Client(peer,request_timeout=1) as client:
    assert client.change_session(3).positive
    assert client.request_seed(1).positive
    assert client.send_key(2,b'\x33\x44').positive
    assert client.request_download(MemoryLocation(0x1000,8,address_format=16,memorysize_format=8)).positive
    assert client.transfer_data(1,b'\x01\x02\x03\x04').positive
    assert client.transfer_data(2,b'\x05\x06\x07\x08').positive
    assert client.request_transfer_exit().positive
root = Path(__file__).resolve().parents[1]
folder = root/'examples'/'client'; folder.mkdir(parents=True,exist_ok=True)
text='\n'.join(peer.log)+'\n'
(folder/'udsoncan-download.log').write_text(text,encoding='utf-8')
bad=text.replace('34 00 12 10 00 08','34 00 12 10 00 09')
assert bad != text
(folder/'download-size-mismatch.log').write_text(bad,encoding='utf-8')
(folder/'source.json').write_text(json.dumps(dict(reference='udsoncan',version='1.26.1',peer='author-written deterministic software ECU',hardware=False,exchanges=len(peer.log)//2),indent=2),encoding='utf-8')
literal=lambda s:json.dumps(s,ensure_ascii=False)
(root/'client_replay_test.mbt').write_text('''// Requests emitted and responses verified by the real udsoncan Client.
test "udsoncan client download is audited from transport-independent payloads" {
  let r = analyze_uds_payload_log('''+literal(text)+''')
  assert_eq(r.verdict,"pass")
  assert_eq(r.transferred_bytes,8)
  assert_eq(r.security_level,1)
}
test "mutating client memorySize is detected despite locally valid responses" {
  let r = analyze_uds_payload_log('''+literal(bad)+''')
  assert_eq(r.verdict,"fail")
  assert_true(r.issues.any(fn(x) { x.code == "TRANSFER_SIZE_MISMATCH" }))
}
''',encoding='utf-8')
print('udsoncan Client completed',len(peer.log)//2,'exchanges; reference trace and mutated counterexample saved')
