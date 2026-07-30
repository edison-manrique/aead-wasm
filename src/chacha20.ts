/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  chacha20.ts — ChaCha20 & XChaCha20 (cifradores de flujo)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Fachada de alto nivel sobre el cifrado de flujo ChaCha20 (nonce 12 B) y
 * XChaCha20 (nonce 24 B). Cifrado y descifrado son la MISMA operación (XOR
 * con el keystream), por lo que `decrypt` es un alias de `encrypt`.
 *
 * ⚠️ ADVERTENCIA DE SEGURIDAD (muy importante):
 * ChaCha20 POR SÍ SOLO NO AUTENTICA. Un atacante puede modificar el
 * ciphertext sin ser detectado (es maleable). Para datos que deban ser
 * confidenciales Y auténticos, usa SIEMPRE el AEAD: ChaCha20-Poly1305 /
 * XChaCha20-Poly1305 (`aead.ts`). Esta clase existe para casos específicos
 * (p. ej. generar keystream, o protocolos que autentican por otro medio).
 *
 * Límite: one-shot hasta ~1 MB (tamaño de PARAM_IN). Para cifrar más, usa el
 * AEAD streaming (`aead.ts`), que cifra por chunks de 1 MB.
 */
import { AeadWasm } from "./aead-wasm"
import { KEY_BYTES, NONCE_BYTES, XNONCE_BYTES, toUint8Array } from "./types"

function assertKey(key: Uint8Array): void {
  if (key.length !== KEY_BYTES) {
    throw new Error(`ChaCha20: la clave debe ser ${KEY_BYTES} bytes (recibidos ${key.length}).`)
  }
}
function assertNonce(nonce: Uint8Array, expected: number): void {
  if (nonce.length !== expected) {
    throw new Error(`ChaCha20: el nonce debe ser ${expected} bytes (recibidos ${nonce.length}).`)
  }
}

/** ChaCha20 — nonce de 12 bytes (RFC 8439). */
export class ChaCha20 {
  /**
   * Cifra (o descifra) datos con ChaCha20.
   * @param key     Clave de 32 bytes.
   * @param nonce   Nonce de 12 bytes (único por mensaje con la misma clave).
   * @param data    Datos (Uint8Array o string UTF-8).
   * @param counter Bloque inicial del keystream (por defecto 0).
   * @returns Datos transformados (mismo tamaño que la entrada).
   */
  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array | string, counter: number = 0): Uint8Array {
    assertKey(key)
    assertNonce(nonce, NONCE_BYTES)
    return AeadWasm.getInstance().chacha20(key, nonce, toUint8Array(data), counter)
  }

  /** Descifrado = cifrado en un cifrador de flujo. */
  static decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array | string, counter: number = 0): Uint8Array {
    return ChaCha20.encrypt(key, nonce, data, counter)
  }
}

/** XChaCha20 — nonce extendido de 24 bytes (más seguro contra colisiones de nonce). */
export class XChaCha20 {
  /**
   * Cifra (o descifra) datos con XChaCha20.
   * @param key   Clave de 32 bytes.
   * @param nonce Nonce de 24 bytes.
   */
  static encrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array | string, counter: number = 0): Uint8Array {
    assertKey(key)
    assertNonce(nonce, XNONCE_BYTES)
    return AeadWasm.getInstance().xchacha20(key, nonce, toUint8Array(data), counter)
  }

  /** Descifrado = cifrado en un cifrador de flujo. */
  static decrypt(key: Uint8Array, nonce: Uint8Array, data: Uint8Array | string, counter: number = 0): Uint8Array {
    return XChaCha20.encrypt(key, nonce, data, counter)
  }
}