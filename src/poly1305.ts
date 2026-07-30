/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  poly1305.ts — Poly1305 (Message Authentication Code, RFC 8439)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Fachada de alto nivel sobre el MAC Poly1305 (tag de 16 bytes).
 *
 * ⚠️ Solo ONE-SHOT en v1: el núcleo exporta `poly1305_mac_ptr` (mensaje
 * completo, hasta ~1 MB). El streaming de Poly1305 *standalone* requeriría
 * exportar `init/update/digest` del núcleo (extensión pendiente); para
 * autenticar archivos grandes hoy se usa el AEAD streaming (aead.ts), que
 * internamente sí autentica por chunks.
 *
 * ⚠️ Poly1305 es un MAC (autenticación), NO cifra. Para cifrado autenticado
 * usa ChaCha20-Poly1305 / XChaCha20-Poly1305 (aead.ts).
 */
import { AeadWasm } from "./aead-wasm"
import { KEY_BYTES, TAG_BYTES, toUint8Array } from "./types"

export class Poly1305 {
  /**
   * Calcula el tag Poly1305 (16 B) de un mensaje con una clave de 32 B.
   * @param key Clave de 32 bytes (r ‖ s).
   * @param msg Mensaje (Uint8Array o string UTF-8).
   * @returns Tag de 16 bytes.
   * @example
   *   const tag = Poly1305.mac(key, "mensaje a autenticar")
   */
  static mac(key: Uint8Array, msg: Uint8Array | string): Uint8Array {
    if (key.length !== KEY_BYTES) {
      throw new Error(`Poly1305: la clave debe ser ${KEY_BYTES} bytes (recibidos ${key.length}).`)
    }
    return AeadWasm.getInstance().poly1305Mac(key, toUint8Array(msg))
  }

  /** Longitud del tag en bytes (16). */
  static get tagLength(): number {
    return TAG_BYTES
  }
}
