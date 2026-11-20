/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  types.ts — Contrato WASM, tipos de dominio y utilidades puras
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Módulo fundacional del wrapper (sin dependencias internas). Contiene:
 *  • AsmExports   — contrato tipado de TODO lo que expone el módulo WASM
 *                   (funciones `_ptr` + globals de I/O). Standalone (NO extiende
 *                   WebAssembly.Exports) para evitar el error TS2411 con los
 *                   globals opcionales; el cargador castea con `as unknown as`.
 *  • Constantes   — longitudes criptográficas fijas (key/nonce/tag/bloque).
 *  • Tipos        — AeadVariant, Detached, interfaces de stream.
 *  • Utilidades   — hex↔bytes, UTF-8, concat y lectura de globals.
 *
 * NOTA de frontera: en el límite WASM↔JS, los punteros (`usize`) y los `bool`
 * viajan como `number`. Por eso los retornos booleanos del WASM se tipan aquí
 * como `number` (0/1) y el wrapper los convierte con `!== 0`.
 */

// ── Firmas de las funciones del WASM (punteros = number) ────────────────────
type CipherPtrFn = (kPtr: number, nPtr: number, inPtr: number, outPtr: number, len: number, counter: number) => void
type AeadOneShotEncryptFn = (
  keyPtr: number,
  noncePtr: number,
  aadPtr: number,
  aadLen: number,
  inPtr: number,
  outPtr: number,
  len: number
) => void
type AeadOneShotDecryptFn = (
  keyPtr: number,
  noncePtr: number,
  aadPtr: number,
  aadLen: number,
  inPtr: number,
  outPtr: number,
  len: number
) => number
type AeadInitFn = (keyPtr: number, noncePtr: number, aadPtr: number, aadLen: number) => number // → ctxPtr
type AeadUpdateFn = (ctxPtr: number, inPtr: number, outPtr: number, len: number) => void
type AeadFinalEncryptFn = (ctxPtr: number, tagOutPtr: number) => void
type AeadFinalDecryptFn = (ctxPtr: number, expectedTagPtr: number) => number // → 0/1

/** Contrato de exports del módulo WASM. */
export interface AsmExports {
  memory: WebAssembly.Memory

  // ── Globals de I/O (memoria plana de 1 MB c/u) ──
  PARAM_IN_PTR?: WebAssembly.Global | number
  PARAM_IN_SIZE?: WebAssembly.Global | number
  PARAM_OUT_PTR?: WebAssembly.Global | number
  PARAM_OUT_SIZE?: WebAssembly.Global | number

  // ── ChaCha20 & XChaCha20 (one-shot) ──
  chacha20_encrypt_ptr: CipherPtrFn
  chacha20_decrypt_ptr: CipherPtrFn
  xchacha20_encrypt_ptr: CipherPtrFn
  xchacha20_decrypt_ptr: CipherPtrFn

  // ── Poly1305 (MAC one-shot) ──
  poly1305_mac_ptr: (msgPtr: number, msgLen: number, keyPtr: number, outPtr: number) => void

  // ── ChaCha20-Poly1305 (one-shot + streaming) ──
  chacha20poly1305_encrypt_ptr: AeadOneShotEncryptFn
  chacha20poly1305_decrypt_ptr: AeadOneShotDecryptFn
  chacha20poly1305_init_encrypt_ptr: AeadInitFn
  chacha20poly1305_init_decrypt_ptr: AeadInitFn
  chacha20poly1305_update_ptr: AeadUpdateFn
  chacha20poly1305_final_encrypt_ptr: AeadFinalEncryptFn
  chacha20poly1305_final_decrypt_ptr: AeadFinalDecryptFn

  // ── XChaCha20-Poly1305 (one-shot + streaming) ──
  xchacha20poly1305_encrypt_ptr: AeadOneShotEncryptFn
  xchacha20poly1305_decrypt_ptr: AeadOneShotDecryptFn
  xchacha20poly1305_init_encrypt_ptr: AeadInitFn
  xchacha20poly1305_init_decrypt_ptr: AeadInitFn
  xchacha20poly1305_update_ptr: AeadUpdateFn
  xchacha20poly1305_final_encrypt_ptr: AeadFinalEncryptFn
  xchacha20poly1305_final_decrypt_ptr: AeadFinalDecryptFn

  // ── Liberación de un stream sin finalizar (opcional; ver nota abajo) ──
  aead_free_ptr?: (ctxPtr: number) => void

  // ── Control de Arena & Lock de memoria ──
  arena_lock?: () => void
  arena_try_lock?: () => number
  arena_unlock?: () => void
  arena_is_locked?: () => number
  arena_used?: () => number
  arena_capacity?: () => number
  arena_is_threaded?: () => number
  arena_reset?: () => void
}

// ── Constantes criptográficas ───────────────────────────────────────────────
export const KEY_BYTES = 32 // clave ChaCha20 / XChaCha20
export const NONCE_BYTES = 12 // nonce ChaCha20-Poly1305
export const XNONCE_BYTES = 24 // nonce XChaCha20-Poly1305
export const TAG_BYTES = 16 // tag Poly1305
export const BLOCK_BYTES = 64 // bloque ChaCha20

// ── Tipos de dominio ────────────────────────────────────────────────────────
/** Variante de AEAD (selección de algoritmo en la API de bajo nivel). */
export type AeadVariant = "chacha" | "xchacha"

/** Estado actual de la Arena WASM y su lock de concurrencia. */
export interface ArenaStats {
  used: number
  capacity: number
  locked: boolean
  threaded: boolean
}

/** Resultado "detached": ciphertext y tag por separado. */
export interface Detached {
  ciphertext: Uint8Array
  tag: Uint8Array
}

/** Stream de cifrado AEAD: `update` por chunks, `final` produce el tag. */
export interface AeadEncryptStream {
  /** Cifra un chunk → devuelve el ciphertext del chunk (mismo tamaño). */
  update(chunk: Uint8Array): Uint8Array
  /** Cierra el stream → devuelve el tag (16 B) y libera el contexto WASM. */
  final(): Uint8Array
  /** Libera el contexto SIN finalizar (abort). Requiere `aead_free_ptr` en el núcleo. */
  free(): void
}

/** Stream de descifrado AEAD: `update` por chunks, `final(tag)` verifica. */
export interface AeadDecryptStream {
  /** Descifra un chunk → devuelve el plaintext del chunk (mismo tamaño). */
  update(chunk: Uint8Array): Uint8Array
  /** Cierra el stream, verifica el tag → validez. Libera el contexto WASM. */
  final(tag: Uint8Array): boolean
  /** Libera el contexto SIN finalizar (abort). Requiere `aead_free_ptr` en el núcleo. */
  free(): void
}

// ── Utilidades: lectura de globals ──────────────────────────────────────────
/** Normaliza un global del WASM a `number` (Global o number plano); fallback si no existe. */
export function getGlobalValue(val: WebAssembly.Global | number | undefined, fallback: number): number {
  if (typeof val === "number") return val
  if (val && typeof val === "object" && "value" in val) return Number(val.value)
  return fallback
}

// ── Utilidades: hex ↔ bytes ─────────────────────────────────────────────────
const HEX_LUT: string[] = []
for (let i = 0; i < 256; i++) HEX_LUT.push(i.toString(16).padStart(2, "0"))

/** Convierte bytes a hex minúsculo (1 lookup por byte). */
export function bytesToHex(bytes: Uint8Array): string {
  let hex = ""
  for (let i = 0; i < bytes.length; i++) hex += HEX_LUT[bytes[i]]
  return hex
}

/** Convierte hex (sin `0x`) a bytes. Longitud impar → antepone un 0. */
export function hexToBytes(hex: string): Uint8Array {
  const clean = hex.length % 2 === 0 ? hex : "0" + hex
  const out = new Uint8Array(clean.length >> 1)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16)
  return out
}

// ── Utilidades: bytes / UTF-8 ───────────────────────────────────────────────
/** String (UTF-8) → Uint8Array; si ya es Uint8Array, la devuelve tal cual (sin copia). */
export function toUint8Array(data: string | Uint8Array): Uint8Array {
  return typeof data === "string" ? new TextEncoder().encode(data) : data
}

/** Concatena varios Uint8Array en uno nuevo (para `ct‖tag` y one-shot grande por chunks). */
export function concatBytes(...parts: Uint8Array[]): Uint8Array {
  let total = 0
  for (let i = 0; i < parts.length; i++) total += parts[i].length
  const out = new Uint8Array(total)
  let offset = 0
  for (let i = 0; i < parts.length; i++) {
    out.set(parts[i], offset)
    offset += parts[i].length
  }
  return out
}
