# 🔐 AEAD WASM

Biblioteca de cifrado autenticado (AEAD) ultra-rápida y de alto rendimiento compilada en WebAssembly (WASM) utilizando AssemblyScript y empaquetada con un wrapper TypeScript Zero-Allocation.

Soporta **ChaCha20-Poly1305** y **XChaCha20-Poly1305** (RFC 8439), los cifradores de flujo **ChaCha20 / XChaCha20** y el MAC **Poly1305** —con **verificación de tags en tiempo constante** (a prueba de _timing attacks_), **streaming de archivos en tiempo real** y **cifrado in-place**— con rendimiento extremo (**~1 M AEAD ops/s** en mensajes pequeños, **~300 MB/s** en streaming de archivos, **~3.1 M Poly1305 ops/s**) y **0 % de presión sobre el Garbage Collector (GC)**.

---

## 🚀 Características Principales

- ⚡ **Máximo Rendimiento**: Núcleo ChaCha20/Poly1305 desplegado en WebAssembly con **~1 M AEAD ops/s** (mensajes de 64 B), **~300 MB/s** en streaming de archivos y **~3.1 M Poly1305 ops/s**, con memoria completamente plana bajo carga.
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: Alocador _arena_ estático (`memory.data` + `save/restore`) y contextos como _struct sobre puntero_ (`changetype`, sin `new` en el heap) — **`WASM Δ 0 B` verificado bajo 500 000 operaciones** en los 5 elementos.
- 🌐 **Multiplataforma**: Funciona sin modificaciones en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, etc.).
- 🛡️ **Seguridad Crypto**:
  - **ChaCha20-Poly1305 / XChaCha20-Poly1305** (RFC 8439) como AEAD principal.
  - **Verificación constant-time** del tag: comparación por XOR acumulativo sin _early-exit_, inmune a ataques de timing.
  - **Limpieza de material sensible**: `wipe()` borra keystream, clave y estado del Poly1305 al cerrar cada operación.
  - Correctitud **validada contra vectores oficiales** (RFC 8439 §A.3/§A.5, vectores de ChaCha20 y XChaCha20-Poly1305) — **128 tests de correctitud + 26 de estrés zero-alloc**.
- 🔄 **Streaming Real**: Cifrado/auth de archivos de cualquier tamaño por chunks (`createEncryptStream`/`createDecryptStream`) — memoria plana, sin acumular buffers.
- 📦 **Binario Compacto**: ~7.8 KB de WebAssembly optimizado (runtime stub).

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

```ts
import { AeadWasm } from "aead-wasm"

// Carga automática desde la URL por defecto (navegador / bundler)
await AeadWasm.load()

// O cargando desde un buffer binario explícito (útil para Node.js / Bun):
// import { readFileSync } from "node:fs"
// const wasmBuffer = readFileSync("node_modules/aead-wasm/dist/aead.wasm")
// await AeadWasm.fromBuffer(wasmBuffer)
```

> La carga se realiza **una sola vez**. Después puedes usar `ChaCha20Poly1305` / `XChaCha20Poly1305` / `ChaCha20` / `XChaCha20` / `Poly1305` directamente (usan el singleton global).

### 2. ChaCha20-Poly1305 (AEAD — RFC 8439)

El caso de uso principal: cifrado **autenticado** (confidencialidad + integridad).

```ts
import { AeadWasm, ChaCha20Poly1305, randomKey, randomNonce } from "aead-wasm"

await AeadWasm.load()

// 🔐 Genera una clave (32 B) y un nonce (12 B) seguros
const key = randomKey()
const nonce = randomNonce() // ⚠️ único por mensaje con la misma clave

// 🔒 Cifra + autentica → combined (ciphertext ‖ tag)
const ct = ChaCha20Poly1305.encrypt(key, nonce, "mensaje secreto", "aad-opcional")

// 🔓 Verifica + descifra → plaintext, o null si el tag es inválido
const pt = ChaCha20Poly1305.decrypt(key, nonce, ct, "aad-opcional")
console.log(new TextDecoder().decode(pt as Uint8Array)) // → "mensaje secreto"

// 🧩 Formato detached (ciphertext y tag por separado)
const { ciphertext, tag } = ChaCha20Poly1305.encryptDetached(key, nonce, "mensaje secreto")
const pt2 = ChaCha20Poly1305.decryptDetached(key, nonce, ciphertext, tag)
```

> 🛡️ El nonce de 12 bytes **debe ser único** por mensaje con la misma clave. Para nonces aleatorios sin riesgo de colisión, usa **XChaCha20-Poly1305** (nonce de 24 B).

### 3. XChaCha20-Poly1305 (nonce extendido de 24 B)

Misma API que ChaCha20-Poly1305, pero con nonce de 24 bytes (HChaCha20 internamente) — ideal para nonces aleatorios.

```ts
import { AeadWasm, XChaCha20Poly1305, randomKey, randomXNonce } from "aead-wasm"

await AeadWasm.load()

const key = randomKey()
const nonce = randomXNonce() // 24 bytes

const ct = XChaCha20Poly1305.encrypt(key, nonce, "mensaje secreto", "aad")
const pt = XChaCha20Poly1305.decrypt(key, nonce, ct, "aad") // → plaintext | null
```

### 4. Streaming de archivos (cifrado/auth en tiempo real)

Cifra o autentica archivos de **cualquier tamaño** por chunks, con memoria plana.

```ts
import { AeadWasm, ChaCha20Poly1305, concatBytes } from "aead-wasm"

await AeadWasm.load()

// 🔒 Cifrado streaming: update por chunks, final produce el tag
const enc = ChaCha20Poly1305.createEncryptStream(key, nonce, aad)
const out: Uint8Array[] = []
for (const chunk of readChunks(file)) out.push(enc.update(chunk))
out.push(enc.final()) // tag de 16 B al final
const ciphertext = concatBytes(...out) // ct ‖ tag

// 🔓 Descifrado streaming: final(tag) verifica al final
const dec = ChaCha20Poly1305.createDecryptStream(key, nonce, aad)
const pt: Uint8Array[] = []
for (const chunk of ctChunks) pt.push(dec.update(chunk))
const ok = dec.final(tag)
if (!ok) throw new Error("tag inválido: descartar el plaintext")
const plaintext = concatBytes(...pt)
```

> ⚠️ **Regla de seguridad del decrypt streaming**: el plaintext se produce en `update` _antes_ de verificar el tag (que llega al final). **No consumas el plaintext hasta que `final(tag)` retorne `true`**; si retorna `false`, descártalo. Inherente al streaming de RFC 8439 (un solo tag final).

### 5. ChaCha20 / XChaCha20 (cifrado de flujo)

Cifrado de flujo puro (sin autenticación).

```ts
import { AeadWasm, ChaCha20, XChaCha20, randomKey, randomNonce } from "aead-wasm"

await AeadWasm.load()

const key = randomKey()
const nonce = randomNonce() // 12 B para ChaCha20, 24 B para XChaCha20

const ct = ChaCha20.encrypt(key, nonce, "datos a cifrar")
const pt = ChaCha20.decrypt(key, nonce, ct) // == encrypt (XOR simétrico)
```

> ⚠️ **Advertencia**: ChaCha20 por sí solo **NO autentica** (es maleable). Para datos que deban ser confidenciales **y** auténticos, usa siempre el AEAD (`ChaCha20Poly1305` / `XChaCha20Poly1305`).

### 6. Poly1305 (MAC — RFC 8439)

Autenticación de mensajes (tag de 16 bytes), sin cifrado.

```ts
import { AeadWasm, Poly1305, randomKey } from "aead-wasm"

await AeadWasm.load()

const key = randomKey() // 32 bytes (r ‖ s)
const tag = Poly1305.mac(key, "mensaje a autenticar") // → Uint8Array(16)
```

### 7. Generación segura de claves y nonces (CSPRNG)

```ts
import { randomKey, randomNonce, randomXNonce, getRandomBytes, fillRandom } from "aead-wasm"

const key = randomKey() // 32 bytes (ChaCha20 / XChaCha20 / Poly1305)
const nonce = randomNonce() // 12 bytes (ChaCha20-Poly1305)
const xnonce = randomXNonce() // 24 bytes (XChaCha20-Poly1305)
const bytes = getRandomBytes(64) // N bytes aleatorios (crypto-safe)
fillRandom(existingBuffer) // rellena un buffer existente (zero-alloc)
```

> El CSPRNG es isomórfico (Node/Bun/Deno/Browser) y hace **fail-fast** si el entorno no expone Web Crypto (`getRandomValues`).

### 8. API de bajo nivel (`AeadWasm`)

Acceso directo a las primitivas del WASM (uso avanzado).

```ts
import { AeadWasm } from "aead-wasm"

const wasm = await AeadWasm.load()

// 🔏 AEAD one-shot (punteros, uso interno)
// wasm.aeadEncrypt("chacha", key, nonce, plaintext, aad?) → Uint8Array (ct ‖ tag)
// wasm.aeadDecrypt("chacha", key, nonce, combined, aad?) → Uint8Array | null

// 🔄 Primitivas de streaming (ctxPtr opaco)
const ctx = wasm.aeadInitEncrypt("xchacha", key, nonce, aad)
const out = wasm.aeadUpdate(ctx, chunk)
const tag = wasm.aeadFinalEncrypt(ctx)
wasm.aeadFree(ctx) // abortar sin finalizar

// 🔑 ChaCha20 / Poly1305 directos
const ct = wasm.chacha20(key, nonce, data, 0) // counter explícito
const mac = wasm.poly1305Mac(key, msg) // → Uint8Array(16)
```

### 9. Utilidades

```ts
import { bytesToHex, hexToBytes, toUint8Array, concatBytes } from "aead-wasm"

const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) // "deadbeef"
const bytes = hexToBytes("deadbeef") // Uint8Array(4)
const utf8 = toUint8Array("texto") // string → Uint8Array (UTF-8)
const joined = concatBytes(a, b, c) // concatena varios Uint8Array
```

---

## 📊 Benchmarks de Rendimiento

Pruebas ejecutadas en **Bun 1.3.3** (JavaScriptCore) sobre x86-64 (win32), single-thread. Binario: **7.8 KB**. Medida a tiempo fijo por tamaño, camino público completo (incluye la copia de salida del wrapper).

| Operación                          | Rendimiento       | Memoria        |
| ---------------------------------- | ----------------- | -------------- |
| Poly1305 (64 B)                    | **~3.1 M ops/s**  | —              |
| ChaCha20 (64 B)                    | **~2.1 M ops/s**  | —              |
| ChaCha20-Poly1305 (64 B)           | **~1.06 M ops/s** | —              |
| ChaCha20-Poly1305 streaming (1 MB) | **~303 MB/s**     | —              |
| Estrés 500 000 ops (5 elementos)   | estable           | **WASM Δ 0 B** |

**One-shot — ops/s por tamaño de mensaje:**

| Operación                    |      64 B |    1 KB |  16 KB | 256 KB |
| ---------------------------- | --------: | ------: | -----: | -----: |
| Poly1305 (mac)               | 3,105,995 | 940,979 | 74,939 |  4,640 |
| ChaCha20 (encrypt)           | 2,127,417 | 348,205 | 25,746 |  1,658 |
| XChaCha20 (encrypt)          | 1,619,413 | 332,500 | 25,526 |  1,655 |
| ChaCha20-Poly1305 (encrypt)  | 1,056,954 | 246,797 | 19,006 |  1,222 |
| ChaCha20-Poly1305 (decrypt)  | 1,069,082 | 246,704 | 19,022 |  1,231 |
| XChaCha20-Poly1305 (encrypt) |   934,416 | 228,195 | 18,991 |  1,233 |
| XChaCha20-Poly1305 (decrypt) |   935,471 | 235,594 | 18,953 |  1,213 |

**One-shot — throughput (MB/s) por tamaño de mensaje:**

| Operación                    |  64 B |  1 KB |  16 KB | 256 KB |
| ---------------------------- | ----: | ----: | -----: | -----: |
| Poly1305 (mac)               | 198.8 | 963.6 | 1227.8 | 1216.3 |
| ChaCha20 (encrypt)           | 136.2 | 356.6 |  421.8 |  434.6 |
| XChaCha20 (encrypt)          | 103.6 | 340.5 |  418.2 |  433.8 |
| ChaCha20-Poly1305 (encrypt)  |  67.6 | 252.7 |  311.4 |  320.3 |
| ChaCha20-Poly1305 (decrypt)  |  68.4 | 252.6 |  311.6 |  322.8 |
| XChaCha20-Poly1305 (encrypt) |  59.8 | 233.7 |  311.1 |  323.1 |
| XChaCha20-Poly1305 (decrypt) |  59.9 | 241.2 |  310.5 |  317.9 |

**Streaming de archivos — AEAD encrypt (MB/s):**

| Operación          |  1 MB |  4 MB |
| ------------------ | ----: | ----: |
| ChaCha20-Poly1305  | 303.0 | 293.4 |
| XChaCha20-Poly1305 | 297.3 | 291.9 |

> El throughput de Poly1305 supera **1.2 GB/s** en mensajes medianos; el AEAD se estabiliza en **~320 MB/s** (one-shot) y **~300 MB/s** (streaming). El `bench` incluye además una comparativa opcional con `node:crypto` (chacha20-poly1305 nativo) cuando el runtime la expone.

**Estrés zero-alloc (verificado en los 5 elementos, 26 tests):**

| Elemento           | Operación         | Rondas     | WASM Δ  | Heap Δ  |
| ------------------ | ----------------- | ---------- | ------- | ------- |
| Poly1305           | mac               | 10K → 500K | **0 B** | < 10 MB |
| ChaCha20           | encrypt           | 10K → 500K | **0 B** | < 10 MB |
| XChaCha20          | encrypt           | 10K → 500K | **0 B** | < 10 MB |
| ChaCha20-Poly1305  | encrypt + decrypt | 10K → 500K | **0 B** | < 10 MB |
| XChaCha20-Poly1305 | encrypt + decrypt | 10K → 500K | **0 B** | < 10 MB |

> La memoria lineal del WASM **nunca crece** (`Δ 0 B`) bajo carga real — la garantía zero-alloc se cumple en los 5 elementos, no solo en el caso feliz.

**Validación de correctitud (128 tests):**

| Estándar                          | Cobertura                                                        |
| --------------------------------- | ---------------------------------------------------------------- |
| Poly1305 — RFC 8439 §A.3          | vectores oficiales + determinismo + sensibilidad + fail-fast     |
| ChaCha20 — RFC 8439 §2.3.2/§2.4.2 | keystream + involución + sensibilidad a key/nonce + counter      |
| ChaCha20-Poly1305 — RFC 8439 §A.5 | encrypt + decrypt + tamper + detached + streaming + AAD-mismatch |
| XChaCha20-Poly1305 — vectores     | encrypt + decrypt + tamper + detached + streaming + AAD-mismatch |

---

## 🏗️ Arquitectura Zero-Allocation

- **Alocador _arena_ estático**: 64 KB de trabajo + 1 MB de entrada (`PARAM_IN`) + 1 MB de salida (`PARAM_OUT`) reservados en el _data segment_ del WASM en **tiempo de compilación** (`memory.data`), con `save()`/`restore()` por operación — ninguna reserva toca el heap del runtime.
- **Contextos como _struct sobre puntero_**: los contextos de ChaCha20/XChaCha20/Poly1305/AEAD se superponen sobre la arena vía `changetype` (sin `new`), eliminando por completo las alocaciones en el heap.
- **Streaming incremental**: el `counter`/`blockPos` de ChaCha20 y el estado de Poly1305 persisten entre chunks; `cipherFinishBlock` separa la authKey (counter 0) del payload (counter 1+).
- **Verificación constant-time**: `secureEqual16` compara el tag calculado con el recibido mediante XOR + OR acumulativo de longitud fija (sin _early-exit_), evitando fugas por timing.
- **Limpieza de material sensible**: `wipe()` borra el keystream pendiente, la clave/nonce (ChaCha20) y el estado del Poly1305 (clave `r`, acumulador) al cerrar cada operación.
- **Única asignación**: el `Uint8Array` de salida que se entrega al usuario (inevitable); todo lo demás vive en la arena.
- **Resultado verificado**: `WASM Δ 0 B` y heap estable bajo 500 000 operaciones en los 5 elementos.

---

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binario WASM (AssemblyScript) + bundle TypeScript (esbuild minificado)
bun run build

# Compilar solo el binario WASM
bun run asbuild          # release → dist/aead.wasm
bun run asbuild:debug    # debug → build/debug.wasm + .wat + sourcemap

# Verificación de tipos
bun run typecheck

# Tests (suite de correctitud + estrés zero-alloc)
bun test

# Benchmark de rendimiento (ops/s · MB/s · streaming · vs node:crypto)
bun run bench            # o: bun test/bench.ts
```

---

## 📁 Estructura del Proyecto

```
aead-wasm/
├── assembly/            # Núcleo en AssemblyScript (→ WebAssembly)
│   ├── index.ts         # Exportaciones WASM (chacha20, poly1305, aead one-shot + streaming)
│   ├── memory.ts        # Alocador arena estático (Memory: alloc/save/restore + PARAM_IN/OUT)
│   ├── chacha.ts        # ChaCha20 & XChaCha20 (HChaCha20, motor incremental, wipe)
│   ├── poly1305.ts      # Poly1305 (radix-2⁶, streaming, wipe)
│   └── aead.ts          # ChaCha20-Poly1305 & XChaCha20-Poly1305 (one-shot + streaming)
├── src/                 # Wrapper en TypeScript
│   ├── index.ts         # Punto de entrada (re-exports)
│   ├── aead-wasm.ts     # Cargador (load/fromUrl/fromBuffer) + API bajo nivel
│   ├── allocator.ts     # WasmAllocator (caché de heap, zero-alloc)
│   ├── chacha20.ts      # ChaCha20 & XChaCha20 (alto nivel)
│   ├── poly1305.ts      # Poly1305 (alto nivel)
│   ├── aead.ts          # ChaCha20Poly1305 & XChaCha20Poly1305 (one-shot + streams)
│   ├── csprng.ts        # CSPRNG isomórfico (randomKey/Nonce/XNonce)
│   └── types.ts         # Tipos (AeadVariant, Detached, streams) + utilidades
├── test/
│   ├── poly1305.test.ts          # Correctitud Poly1305 (RFC 8439 §A.3)
│   ├── chacha20.test.ts          # Correctitud ChaCha20 (RFC 8439 §2.3.2/§2.4.2)
│   ├── chacha20poly1305.test.ts  # Correctitud AEAD (RFC 8439 §A.5)
│   ├── xchacha20poly1305.test.ts # Correctitud XChaCha20-Poly1305
│   ├── memory.test.ts            # Estrés zero-alloc (WASM Δ 0 B, 5 elementos)
│   ├── bench.ts                  # Benchmark de rendimiento
│   └── vectors/                  # Vectores de test oficiales
│       ├── vectors_poly1305.ts
│       ├── vectors_chacha20.ts
│       ├── vectors_chacha20poly1305.ts
│       └── vectors_xchacha20poly1305.ts
├── dist/                # Build (generado)
├── asconfig.json        # Configuración de AssemblyScript
├── package.json
├── tsconfig.json
├── LICENSE              # Apache-2.0
└── README.md
```

---

## 📜 Licencia

[Apache License 2.0](./LICENSE) © **Edison Manrique**

> **Exención de responsabilidad:** este software se proporciona "tal cual" (AS IS), sin garantía de ningún tipo. Aunque ChaCha20-Poly1305, XChaCha20-Poly1305 y Poly1305 son estándares (RFC 8439), esta implementación no ha sido auditada formalmente y no debe emplearse en aplicaciones de seguridad crítica sin verificación independiente.
