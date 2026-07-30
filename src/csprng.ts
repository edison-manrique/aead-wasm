/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  csprng.ts — Generador de Números Aleatorios Criptográficamente Seguro
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Módulo universal (isomórfico) sin dependencias nativas atadas. Funciona en
 * Node.js, Bun, Deno y Navegadores sin activar polyfills pesados en CDNs
 * (esm.sh) ni bundlers (Vite/Webpack): siempre `Uint8Array`, nunca `Buffer`.
 *
 * SEGURIDAD FAIL-FAST: si el entorno no expone Web Crypto (`getRandomValues`),
 * se lanza en la inicialización del módulo. Un CSPRNG ausente o débil rompe
 * por completo la seguridad de ChaCha20-Poly1305 (nonces predecibles = clave
 * comprometida), así que fallar temprano es la única opción correcta.
 *
 * En AEAD la aleatoriedad segura se usa para generar:
 *  • claves   (32 bytes)  → randomKey()
 *  • nonces   (12 bytes)  → randomNonce()      [ChaCha20-Poly1305]
 *  • nonces X (24 bytes)  → randomXNonce()     [XChaCha20-Poly1305]
 * El nonce DEBE ser único por mensaje con la misma clave; lo ideal es aleatorio.
 */

/** Firma de un generador de bytes aleatorios. */
export type RandomBytesGenerator = (size: number) => Uint8Array

/** Límite de bytes por llamada de la Web Crypto API (64 KB). */
const CHUNK = 65536

/**
 * Inyector de entropía nativo, capturado una sola vez (IIFE).
 * Closure monomórfica para que el JIT la inline en el hot path.
 */
const _getRandomValues = (() => {
  const cryptoObj = typeof globalThis !== "undefined" ? globalThis.crypto : undefined

  if (!cryptoObj || typeof cryptoObj.getRandomValues !== "function") {
    throw new Error("CRÍTICO: Criptografía segura (CSPRNG / Web Crypto) no disponible en este entorno.")
  }

  return (buf: Uint8Array): Uint8Array => {
    // Rellena in-place. El cast aísla la restricción de SharedArrayBuffer de las
    // libs TS ≥5.7: nuestros buffers SIEMPRE están respaldados por ArrayBuffer.
    cryptoObj.getRandomValues(buf as Uint8Array<ArrayBuffer>)
    return buf
  }
})()

/**
 * Genera un array de `size` bytes criptográficamente seguros (nueva asignación).
 *
 * Ruta rápida (≤ 64 KB): una sola llamada a `getRandomValues`.
 * Ruta lenta  (> 64 KB): chunking de 64 KB (límite de la Web Crypto API).
 *
 * @example const key = getRandomBytes(32)
 */
export function getRandomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size)
  return fillRandom(bytes)
}

/**
 * Rellena un buffer EXISTENTE con entropía (zero-alloc: no crea array nuevo).
 * Útil para reusar buffers o llenar estructuras pre-reservadas.
 *
 * @returns el mismo buffer pasado (encadenable).
 */
export function fillRandom(buf: Uint8Array): Uint8Array {
  const size = buf.length
  if (size <= CHUNK) {
    _getRandomValues(buf)
    return buf
  }
  for (let offset = 0; offset < size; offset += CHUNK) {
    const end = offset + CHUNK > size ? size : offset + CHUNK
    _getRandomValues(buf.subarray(offset, end))
  }
  return buf
}

// ── Helpers de dominio AEAD ─────────────────────────────────────────────────

/** Genera una clave de 32 bytes (256 bits) para ChaCha20 / XChaCha20. */
export function randomKey(): Uint8Array {
  return getRandomBytes(32)
}

/** Genera un nonce de 12 bytes (96 bits) para ChaCha20-Poly1305. */
export function randomNonce(): Uint8Array {
  return getRandomBytes(12)
}

/** Genera un nonce extendido de 24 bytes (192 bits) para XChaCha20-Poly1305. */
export function randomXNonce(): Uint8Array {
  return getRandomBytes(24)
}
