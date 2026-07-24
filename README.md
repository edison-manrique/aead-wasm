# 🔐 AEAD WASM

> Biblioteca criptográfica ultra-rápida y de alto rendimiento compilada en **WebAssembly (WASM)** utilizando **AssemblyScript** y empaquetada con un wrapper TypeScript **Zero-Allocation**.

Soporta **ChaCha20**, **XChaCha20**, **Poly1305**, **ChaCha20-Poly1305 AEAD** y **XChaCha20-Poly1305 AEAD** con rendimiento extremo (> 290 MB/s en cifrado de bloques) y 0% de presión sobre el Garbage Collector (GC).

---

## 🚀 Características Principal

- ⚡ **Máximo Rendimiento**: Cifrado escalar vectorizado en WebAssembly con más de 290 MB/s de throughput.
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: Usa un asignador de memoria scratchpad (`WasmAllocator`) y `LocalArena` dentro de WASM para evitar instanciar objetos intermedios.
- 🌐 **Multiplataforma**: Funciona sin modificaciones en **Node.js**, **Bun**, **Deno** y **Navegadores Web** (Vite, Webpack, etc.).
- 🛡️ **Seguridad Crypto**:
  - Detección de alteraciones (Tampering) en tiempo constante.
  - Implementación Poly1305 V5 sin desbordamientos ni Register Spilling.
  - Soporte para Nonce Extendido de 192 bits (**XChaCha20-Poly1305**) seguro para generación de nonces aleatorios.

---

## 📦 Instalación

```bash
npm install aead-wasm
```

O con Bun / Yarn / pnpm:

```bash
bun add aead-wasm
```

---

## 💻 Guía de Uso

### 1. Inicializar la biblioteca

```typescript
import ChaChaPolyWasm from "aead-wasm"

// Carga automática (en entornos Node.js / Bun o navegador)
const crypto = await ChaChaPolyWasm.load()

// O cargando desde un buffer binario explícito (útil para bundlers):
// const wasmBuffer = fs.readFileSync("./dist/aead.wasm")
// const crypto = await ChaChaPolyWasm.fromBuffer(wasmBuffer)
```

---

### 2. ChaCha20-Poly1305 AEAD (RFC 8439)

Ideal para cifrado autenticado estándar con nonce de 12 bytes.

```typescript
// Clave de 32 bytes y Nonce de 12 bytes
const key = crypto.getRandomValues(new Uint8Array(32)) // o crypto.getRandomValues de Web Crypto
const nonce = new Uint8Array(12) // Debe ser único por mensaje
const plaintext = new TextEncoder().encode("Mensaje secreto de alto valor 🤫")
const aad = new TextEncoder().encode("header-metadata-v1")

// 🔐 Cifrar (retorna ciphertext + 16 bytes de tag Poly1305)
const sealed = crypto.chacha20Poly1305Encrypt(key, nonce, plaintext, aad)

// 🔓 Descifrar (verifica el tag ANTES de descifrar)
const decrypted = crypto.chacha20Poly1305Decrypt(key, nonce, sealed, aad)

if (decrypted !== null) {
  console.log("Descifrado exitoso:", new TextDecoder().decode(decrypted))
} else {
  console.error("❌ Fallo de autenticación: los datos o el AAD fueron alterados")
}
```

---

### 3. XChaCha20-Poly1305 AEAD (Nonce Extendido de 24 Bytes)

Recomendado cuando los nonces se generan de forma aleatoria (24 bytes / 192 bits), eliminando el riesgo de colisión de nonce.

```typescript
const key = new Uint8Array(32) // Clave de 32 bytes
const nonce = new Uint8Array(24) // Nonce extendido de 24 bytes (seguro para randomBytes)
const plaintext = new TextEncoder().encode("Datos protegidos con XChaCha20-Poly1305")

// Cifrar
const sealed = crypto.xchacha20Poly1305Encrypt(key, nonce, plaintext)

// Descifrar
const decrypted = crypto.xchacha20Poly1305Decrypt(key, nonce, sealed)
console.log(new TextDecoder().decode(decrypted))
```

---

### 4. Poly1305 MAC (Message Authentication Code)

Genera un tag de autenticación determinístico de 16 bytes.

```typescript
const key = new Uint8Array(32) // Clave de un solo uso de 32 bytes
const message = new TextEncoder().encode("Mensaje a autenticar")

const tag = crypto.poly1305Mac(message, key) // Uint8Array(16)
```

---

### 5. ChaCha20 / XChaCha20 Stream Ciphers

Cifradores de flujo puros (operación simétrica).

```typescript
// ChaCha20 (Nonce 12B)
const ciphertext = crypto.chacha20Encrypt(key, nonce12, data)
const original = crypto.chacha20Decrypt(key, nonce12, ciphertext)

// XChaCha20 (Nonce 24B)
const xciphertext = crypto.xchacha20Encrypt(key, nonce24, data)
const xoriginal = crypto.xchacha20Decrypt(key, nonce24, xciphertext)
```

---

## 📊 Benchmarks de Rendimiento

Pruebas ejecutadas en procesador moderno (ops/sec y throughput):

| Algoritmo              | Tamaño de Bloque | Ops/seg        | Throughput     |
| ---------------------- | ---------------- | -------------- | -------------- |
| **ChaCha20-Poly1305**  | 1 KB             | ~127,000 ops/s | 130.2 MB/s     |
| **XChaCha20-Poly1305** | 1 KB             | ~125,000 ops/s | 128.8 MB/s     |
| **ChaCha20-Poly1305**  | 64 KB            | ~4,480 ops/s   | **293.8 MB/s** |
| **XChaCha20-Poly1305** | 64 KB            | ~4,500 ops/s   | **295.3 MB/s** |

---

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binario WASM y bundle TypeScript (con esbuild minificado)
npm run build

# Compilar solo el binario WASM de AssemblyScript
npm run asbuild

# Ejecutar la suite de tests y benchmarks de demostración
bun examples/demo.js
```

---

## 📜 Licencia

[Apache License 2.0](LICENSE) © Edison Manrique
