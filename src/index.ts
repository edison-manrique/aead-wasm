/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada público de aead-wasm
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Re-exporta la API pública del paquete. Este archivo es el `main`/`exports`
 * del package.json: lo que el usuario importa con
 *   import { AeadWasm, XChaCha20Poly1305, randomKey, randomXNonce } from "aead-wasm"
 *
 * Mapa de módulos internos → qué se expone:
 *   aead-wasm.ts → AeadWasm                 (cargador + API de bajo nivel)
 *   chacha20.ts  → ChaCha20, XChaCha20      (cifrado de flujo; ⚠️ no autentica)
 *   poly1305.ts  → Poly1305                 (MAC one-shot)
 *   aead.ts      → ChaCha20Poly1305,        (cifrado autenticado: one-shot +
 *                  XChaCha20Poly1305          detached + streaming)
 *   csprng.ts    → randomKey/Nonce/XNonce, getRandomBytes, fillRandom
 *   types.ts     → constantes + utilidades (hex/bytes/concat) + tipos
 *
 * Qué NO se expone (y por qué):
 *   • AsmExports / getGlobalValue → contrato interno del WASM.
 *   • WasmAllocator               → interno; accesible vía
 *                                   AeadWasm.getInstance().getAllocator().
 *   • *_ptr / AeadVariant de bajo nivel se mantienen fuera salvo AeadVariant
 *     (útil si alguien usa la API de bajo nivel de AeadWasm).
 *
 * Happy path (cifrado autenticado con XChaCha20-Poly1305):
 *   import { AeadWasm, XChaCha20Poly1305, randomKey, randomXNonce, bytesToHex } from "aead-wasm"
 *
 *   await AeadWasm.load()                                  // 1) cargar el WASM (una vez)
 *   const key   = randomKey()                              // 2) clave de 32 B
 *   const nonce = randomXNonce()                           //    nonce de 24 B (único por msg)
 *   const ct    = XChaCha20Poly1305.encrypt(key, nonce, "secreto", "aad") // 3) ct ‖ tag
 *   const pt    = XChaCha20Poly1305.decrypt(key, nonce, ct, "aad")        // 4) plaintext | null
 *
 * Streaming (archivos grandes, memoria plana):
 *   const enc = XChaCha20Poly1305.createEncryptStream(key, nonce, aad)
 *   for (const chunk of chunks) sink.write(enc.update(chunk))
 *   sink.write(enc.final())                                // tag al final
 */

// ── Cargador + API de bajo nivel ────────────────────────────────────────────
export { AeadWasm } from "./aead-wasm"

// ── Cifradores de flujo (⚠️ no autentican; para datos auténticos usa el AEAD) ─
export { ChaCha20, XChaCha20 } from "./chacha20"

// ── MAC Poly1305 (one-shot) ─────────────────────────────────────────────────
export { Poly1305 } from "./poly1305"

// ── Cifrado autenticado (AEAD): one-shot + detached + streaming ─────────────
export { ChaCha20Poly1305, XChaCha20Poly1305 } from "./aead"

// ── Generación segura de claves y nonces (CSPRNG) ───────────────────────────
export { getRandomBytes, fillRandom, randomKey, randomNonce, randomXNonce } from "./csprng"

// ── Constantes criptográficas ───────────────────────────────────────────────
export { KEY_BYTES, NONCE_BYTES, XNONCE_BYTES, TAG_BYTES, BLOCK_BYTES } from "./types"

// ── Utilidades de conversión ────────────────────────────────────────────────
export { bytesToHex, hexToBytes, toUint8Array, concatBytes } from "./types"

// ── Tipos de dominio (separados para verbatimModuleSyntax / isolatedModules) ─
export type { AeadVariant, ArenaStats, Detached, AeadEncryptStream, AeadDecryptStream } from "./types"
export type { RandomBytesGenerator } from "./csprng"
