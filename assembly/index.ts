/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada del módulo WASM (aead-wasm)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Re-exporta TODAS las funciones criptográficas y las regiones de memoria.
 * Compilado por `asc assembly/index.ts --target release` (runtime `stub`).
 *
 * 100% API DE PUNTEROS (zero-alloc) y nombres en `snake_case`. La conversión
 * Uint8Array ↔ puntero y las validaciones de longitud viven en el wrapper TS.
 */

// ── Memoria / I/O (el wrapper copia aquí los datos del usuario) ────────────
export { PARAM_IN_PTR, PARAM_IN_SIZE, PARAM_OUT_PTR, PARAM_OUT_SIZE } from "./memory"

// ── ChaCha20 & XChaCha20 (cifradores de flujo, one-shot) ───────────────────
export { chacha20_encrypt_ptr, chacha20_decrypt_ptr, xchacha20_encrypt_ptr, xchacha20_decrypt_ptr } from "./chacha"

// ── Poly1305 (MAC, one-shot) — alias a snake_case por convención ───────────
export { poly1305_mac_ptr } from "./poly1305"

// ── ChaCha20-Poly1305 (AEAD) — one-shot + streaming ────────────────────────
export {
  chacha20poly1305_encrypt_ptr,
  chacha20poly1305_decrypt_ptr,
  chacha20poly1305_init_encrypt_ptr,
  chacha20poly1305_init_decrypt_ptr,
  chacha20poly1305_update_ptr,
  chacha20poly1305_final_encrypt_ptr,
  chacha20poly1305_final_decrypt_ptr,
  aead_free_ptr
} from "./aead"

// ── XChaCha20-Poly1305 (AEAD) — one-shot + streaming ───────────────────────
export {
  xchacha20poly1305_encrypt_ptr,
  xchacha20poly1305_decrypt_ptr,
  xchacha20poly1305_init_encrypt_ptr,
  xchacha20poly1305_init_decrypt_ptr,
  xchacha20poly1305_update_ptr,
  xchacha20poly1305_final_encrypt_ptr,
  xchacha20poly1305_final_decrypt_ptr
} from "./aead"
