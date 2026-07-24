// =============================================================================
// 🚀 PUNTO DE ENTRADA — ASSEMBLY/INDEX.TS
// =============================================================================
// Re-exporta TODAS las funciones criptográficas optimizadas del módulo WASM.
// Este es el archivo compilado por `asc assembly/index.ts --target release`.
// =============================================================================

// ── ChaCha20 & XChaCha20 (Cifradores de flujo) ─────────────────────────────
export {
  chacha20_encrypt,
  chacha20_decrypt,
  xchacha20_encrypt,
  xchacha20_decrypt
} from "./chacha"

// ── Poly1305 (MAC) ──────────────────────────────────────────────────────────
export {
  Poly1305_mac,
  Poly1305_mac_ptr
} from "./poly1305"

// ── ChaCha20-Poly1305 & XChaCha20-Poly1305 (AEAD) ──────────────────────────
export {
  chacha20poly1305_encrypt,
  chacha20poly1305_decrypt,
  xchacha20poly1305_encrypt,
  xchacha20poly1305_decrypt
} from "./aead"
