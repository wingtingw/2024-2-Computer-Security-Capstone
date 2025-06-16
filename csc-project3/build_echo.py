import os
import struct

stub = "stub.sh"
payload = "payload.sh"
output = "happy_echo"
sig_file = "signature.sig"
target_size = 67792
sig_size = 512
unsigned_max = target_size - sig_size

with open(stub, "rb") as f: s = f.read()
with open(payload, "rb") as f: p = f.read()

offset = len(s)
size = len(p)
footer = struct.pack("<II", offset, size)

# Final body
unsigned = s + p + footer

if len(unsigned) > unsigned_max:
    raise ValueError(f"Too large: {len(unsigned)} > {unsigned_max}")

unsigned = unsigned.ljust(unsigned_max, b'\x00')

# Sign
with open("tmp_unsigned", "wb") as f: f.write(unsigned)
os.system(f"openssl dgst -sign dilithium3_priv.pem -out {sig_file} tmp_unsigned")
with open(sig_file, "rb") as f:
    sig = f.read()

if len(sig) < 512:
    raise ValueError(f"Signature too short: {len(sig)} bytes")
elif len(sig) > 512:
    print(f"[!] Signature is too long ({len(sig)} bytes), truncating to 512.")
    sig = sig[:512]


# Final output
final = unsigned + sig
print("[*] stub:", len(s))
print("[*] payload:", len(p))
print("[*] offset + size:", len(footer))
print("[*] unsigned (before pad):", len(unsigned))
print("[*] unsigned_max:", unsigned_max)
print("[*] signature:", len(sig))
print("[*] final:", len(final))

assert len(final) == target_size

with open(output, "wb") as f: f.write(final)
os.chmod(output, 0o755)

print(f"[+] Final happy_echo size: {len(final)} bytes")
