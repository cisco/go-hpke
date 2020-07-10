import sys
import json
import textwrap

ordered_keys = [
    # Mode and ciphersuite parameters
    "mode", "kemID", "kdfID", "aeadID", "info",
    # Private key material
    "seedE", "pkE", "skE",
    "seedR", "pkR", "skR",
    "seedS", "pkS", "skS",
    "psk", "pskID",
    # Derived context
    "enc", "zz", "keyScheduleContext", "secret", "key", "nonce", "exporterSecret",
]

ordered_encryption_keys = [
    "plaintext", "aad", "nonce", "ciphertext",
]

encryption_count_keys = [
    0, 1, 2, 4, 10, 32, 255, 256, 257
]

def entry_kem(entry):
    return kemMap[entry["kemID"]]

def entry_kem_value(entry):
    return entry["kemID"]

def entry_kdf(entry):
    return kdfMap[entry["kdfID"]]

def entry_kdf_value(entry):
    return entry["kdfID"]

def entry_aead(entry):
    return aeadMap[entry["aeadID"]]

def entry_aead_value(entry):
    return entry["aeadID"]

def entry_mode(entry):
    return modeMap[entry["mode"]]

def entry_mode_value(entry):
    return entry["mode"]

modeBase = 0x00
modePSK = 0x01
modeAuth = 0x02
modeAuthPSK = 0x03
modeMap = {modeBase: "Base", modePSK: "PSK", modeAuth: "Auth", modeAuthPSK: "AuthPSK"}

kemIDP256 = 0x0010
kemIDP521 = 0x0012
kemIDCurve25519 = 0x0020
kemMap = {kemIDCurve25519: "DHKEM(Curve25519, HKDF-SHA256)", kemIDP256: "DHKEM(P-256, HKDF-SHA256)", kemIDP521: "DHKEM(P-521, HKDF-SHA512)"}

kdfIDSHA256 = 0x0001
kdfIDSHA512 = 0x0003
kdfMap = {kdfIDSHA256: "HKDF-SHA256", kdfIDSHA512: "HKDF-SHA512"}

aeadIDAESGCM128 = 0x0001
aeadIDAESGCM256 = 0x0002
aeadIDChaCha20Poly1305 = 0x0003
aeadMap = {aeadIDAESGCM128: "AES-GCM-128", aeadIDAESGCM256: "AES-GCM-256", aeadIDChaCha20Poly1305: "ChaCha20Poly1305"}

class CipherSuite(object):
    def __init__(self, kemID, kdfID, aeadID):
        self.kemID = kemID
        self.kdfID = kdfID
        self.aeadID = aeadID

    def __str__(self):
        return kemMap[self.kemID] + ", " + kdfMap[self.kdfID] + ", " + aeadMap[self.aeadID]

    def __repr__(self):
        return str(self)

    def matches_vector(self, vector):
        return self.kemID == entry_kem_value(vector) and self.kdfID == entry_kdf_value(vector) and self.aeadID == entry_aead_value(vector)

testSuites = [
    CipherSuite(kemIDCurve25519, kdfIDSHA256, aeadIDAESGCM128),
    CipherSuite(kemIDCurve25519, kdfIDSHA256, aeadIDChaCha20Poly1305),
    CipherSuite(kemIDP256, kdfIDSHA256, aeadIDAESGCM128),
    CipherSuite(kemIDP256, kdfIDSHA256, aeadIDChaCha20Poly1305),
    CipherSuite(kemIDP521, kdfIDSHA512, aeadIDAESGCM256),
]

def wrap_line(value):
    return textwrap.fill(value, width=72)

def format_encryption(entry, count):
    formatted = wrap_line("sequence number: %d" % count) + "\n"
    for key in ordered_encryption_keys:
        if key in entry:
            formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
    return formatted

def format_encryptions(entry, mode):
    formatted = "~~~\n"
    for seq_number in encryption_count_keys:
        for i, encryption in enumerate(entry["encryptions"]):
            if i == seq_number:
                formatted = formatted + format_encryption(encryption, i)
                if i < len(entry["encryptions"]) - 1:
                    formatted = formatted + "\n"
    return formatted + "~~~"

def format_vector(entry, mode):
    formatted = "~~~\n"
    for key in ordered_keys:
        if key in entry:
            formatted = formatted + wrap_line(key + ": " + str(entry[key])) + "\n"
    return formatted + "~~~\n"

with open(sys.argv[1], "r") as fh:
    data = json.load(fh)
    for suite in testSuites:
        print("## " + str(suite))
        print("")
        for mode in [modeBase, modePSK, modeAuth, modeAuthPSK]:
            for vector in data:
                if suite.matches_vector(vector):
                    if mode == entry_mode_value(vector):
                        print("### " + modeMap[mode] + " Setup Information")
                        print(format_vector(vector, mode))
                        print("#### Encryptions")
                        print(format_encryptions(vector, mode))
                        print("")
