/**
 * ═══════════════════════════════════════════════════════════════════════════
 *  index.ts — Punto de entrada del módulo WASM (aead-wasm)
 * ═══════════════════════════════════════════════════════════════════════════
 *
 * Re-exporta TODAS las funciones criptográficas, regiones de memoria I/O y
 * primitivas de sincronización/lock de `Arena` (single-slot ST / multi-slot MT).
 */
import { Arena } from "./arena"

// ── Memoria / I/O (Slot 0 y helpers multi-slot) ─────────────────────────────
export { PARAM_IN_PTR, PARAM_IN_SIZE, PARAM_OUT_PTR, PARAM_OUT_SIZE } from "./arena"

// ── Control de Arena, Slots & Lock de memoria ───────────────────────────────
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
export function arena_ctrl_ptr(): usize {
  return Arena.ctrlPtr()
}
export function arena_worker_hint_ptr(): usize {
  return Arena.workerHintPtr()
}
export function arena_off_ptr(): usize {
  return Arena.offPtr()
}
export function arena_slot_count(): i32 {
  return Arena.slotCount()
}
export function arena_slot_in_ptr(slot: i32): usize {
  return Arena.slotInPtr(slot)
}
export function arena_slot_out_ptr(slot: i32): usize {
  return Arena.slotOutPtr(slot)
}
export function arena_use_slot(slot: i32): void {
  Arena.useSlot(slot)
}
export function arena_sync_slot(): void {
  Arena.syncSlot()
}
export function arena_slot_for_ptr(ptr: usize): i32 {
  return Arena.slotForPtr(ptr)
}

// ── ChaCha20 & XChaCha20 (cifradores de flujo, one-shot) ───────────────────
export { chacha20_encrypt_ptr, chacha20_decrypt_ptr, xchacha20_encrypt_ptr, xchacha20_decrypt_ptr } from "./chacha"

// ── Poly1305 (MAC, one-shot) ────────────────────────────────────────────────
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
