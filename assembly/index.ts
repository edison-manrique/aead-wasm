/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada del módulo WASM (aead-wasm)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Re-exporta TODAS las funciones criptográficas, regiones de memoria I/O y
 * primitivas de sincronización/lock de `Arena`.
 * Compilado en dos variantes:
 *  • Single-thread (`--target release`    → dist/aead.wasm)
 *  • Multithread   (`--target release-mt` → dist/aead.mt.wasm)
 *
 * 100% API DE PUNTEROS (zero-alloc) y nombres en `snake_case`. La conversión
 * Uint8Array ↔ puntero y las validaciones de longitud viven en el wrapper TS.
 */
import { Arena } from "./arena"

// ── Memoria / I/O (el wrapper copia aquí los datos del usuario) ────────────
export { PARAM_IN_PTR, PARAM_IN_SIZE, PARAM_OUT_PTR, PARAM_OUT_SIZE } from "./arena"

// ── Control de Arena & Lock de memoria (evita sobreescrituras concurrentes) ─
export function arena_lock(): void {
  Arena.lock()
}
export function arena_try_lock(): bool {
  return Arena.tryLock()
}
export function arena_unlock(): void {
  Arena.unlock()
}
export function arena_is_locked(): bool {
  return Arena.isLocked()
}
export function arena_used(): usize {
  return Arena.used()
}
export function arena_capacity(): usize {
  return Arena.capacity()
}
export function arena_is_threaded(): bool {
  return Arena.isThreaded()
}
export function arena_reset(): void {
  Arena.reset()
}

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
