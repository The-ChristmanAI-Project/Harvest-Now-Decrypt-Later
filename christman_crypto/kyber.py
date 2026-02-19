"""
KYBER HANDSHAKE  |  The Christman AI Project
Powered by Luma Cognify AI

Drop-in compatible with kyber_py. Falls back to pq_layer FIPS 203.
"""

import os
import hashlib
import logging
from typing import Tuple

logger = logging.getLogger(__name__)

# BACKEND SELECTION
_BACKEND = None

try:
    from kyber_py.ml_kem import ML_KEM_512 as _KP_512
    from kyber_py.ml_kem import ML_KEM_768 as _KP_768
    from kyber_py.ml_kem import ML_KEM_1024 as _KP_1024
    _BACKEND = "kyber_py"
    logger.info("ML-KEM backend: kyber_py (installed)")
except ImportError:
    try:
        import sys
        _here = os.path.dirname(os.path.abspath(__file__))
        if _here not in sys.path:
            sys.path.insert(0, _here)
        from christman_crypto.postquantum import MLKEM as _MLKEM_IMPL
        _BACKEND = "pq_layer"
        logger.info("ML-KEM backend: pq_layer (built-in FIPS 203)")
    except ImportError:
        raise ImportError("No ML-KEM backend. pip install kyber-py or add pq_layer.py")

class _MLKEMAdapter:
    def __init__(self, level: int):
        self._kem = _MLKEM_IMPL(level)
        self._level = level

    def keygen(self) -> Tuple :
        return self._kem.keygen()

    def encaps(self, ek: bytes) -> Tuple :
        ct, ss = self._kem.encapsulate(ek)
        return ss, ct  # kyber_py order

    def decaps(self, dk: bytes, ct: bytes) -> bytes:
        return self._kem.decapsulate(dk, ct)

    def __repr__(self):
        return f"ML_KEM_{self._level} "

if _BACKEND == "kyber_py":
    ML_KEM_512 = _KP_512
    ML_KEM_768 = _KP_768
    ML_KEM_1024 = _KP_1024
else:
    ML_KEM_512 = _MLKEMAdapter(512)
    ML_KEM_768 = _MLKEMAdapter(768)
    ML_KEM_1024 = _MLKEMAdapter(1024)

class KyberHandshake:
    def __init__(self, security_level: int = 768):
        if security_level == 512:
            self.kem = ML_KEM_512
        elif security_level == 768:
            self.kem = ML_KEM_768
        elif security_level == 1024:
            self.kem = ML_KEM_1024
        else:
            raise ValueError("security_level must be 512, 768, or 1024")
        self._level = security_level
        logger.info(f"KyberHandshake ML-KEM-{security_level} | backend={_BACKEND}")

    def generate_keys(self) -> Tuple :
        ek, dk = self.kem.keygen()
        logger.debug(f"Keys: ek={len(ek)}B dk={len(dk)}B")
        return ek, dk

    def encapsulate(self, ek: bytes) -> Tuple :
        ss, ct = self.kem.encaps(ek)
        logger.debug(f"Encap: ss={len(ss)}B ct={len(ct)}B")
        return ss, ct

    def decapsulate(self, dk: bytes, ct: bytes) -> bytes:
        ss = self.kem.decaps(dk, ct)
        logger.debug(f"Decap: ss={len(ss)}B")
        return ss

    def derive_session_key(self, ss: bytes, info: bytes = b"christman-ai-session") -> bytes:
        import hmac
        prk = hmac.new(b'\x00'*32, ss, hashlib.sha256).digest()
        return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()

    def __repr__(self):
        return f"KyberHandshake(ML-KEM-{self._level}, {_BACKEND})"

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format=' %(message)s')

    print(f"\nBackend: {_BACKEND}\n")
    for level in [512, 768, 1024]:
        print(f"{'═'*60}")
        print(f"ML-KEM-{level} Handshake")
        print(f"{'═'*60}")

        hs = KyberHandshake(level)
        ek, dk = hs.generate_keys()
        print(f"EK: {ek.hex()[:64]}...")
        ss, ct = hs.encapsulate(ek)
        print(f"CT: {ct.hex()[:64]}...")
        recovered = hs.decapsulate(dk, ct)
        assert ss == recovered
        print(f"SS match: {recovered.hex()[:64]}... ✓")

        key = hs.derive_session_key(recovered)
        print(f"Derived key: {key.hex()[:64]}...\n")

    print(f"{'═'*60}")
    print("All levels: PASSED")
    print("The Christman AI Project — fork this shit.")
    print(f"{'═'*60}\n")