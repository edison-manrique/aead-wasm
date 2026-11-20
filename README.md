# 🔐 AEAD WASM

Biblioteca de cifrado autenticado (AEAD) ultra-rápida y de alto rendimiento compilada en WebAssembly (WASM) utilizando AssemblyScript y empaquetada con un wrapper TypeScript Zero-Allocation, disponible en variantes **Single-Thread** (`aead.wasm`) y **Multithread** (`aead.mt.wasm`).

Soporta **ChaCha20-Poly1305** y **XChaCha20-Poly1305** (RFC 8439), los cifradores de flujo **ChaCha20 / XChaCha20** y el MAC **Poly1305** —con **verificación de tags en tiempo constante** (a prueba de _timing attacks_), **streaming de archivos en tiempo real**, **cifrado in-place** y **lock exclusivo en `Arena`** contra sobreescrituras concurrentes— con **0 % de presión sobre el Garbage Collector (GC)**.

---

## 🚀 Características Principales

- ⚡ **Doble Compilación (ST & MT)**:
  - **Single-Thread (`dist/aead.wasm`, 8.1 KB)**: cero instrucciones atómicas, ideal para uso secuencial y entornos sin `SharedArrayBuffer`.
  - **Multithread (`dist/aead.mt.wasm`, 9.1 KB)**: compilado con `--enable threads --sharedMemory --importMemory --zeroFilledMemory` para compartir memoria lineal (`SharedArrayBuffer`) entre Web Workers o `node:worker_threads`.
- 🔒 **Lock de Memoria en `Arena` (`assembly/arena.ts`)**:
  - Protege `PARAM_IN`, `PARAM_OUT` y el bump-pointer compartido frente a sobreescrituras mientras hay una operación en curso (`arena_lock` / `arena_try_lock` / `arena_unlock`).
- 🧹 **Zero-Alloc (Cero Alocaciones GC)**: Alocador estático `Arena` (`memory.data` + `save/restore`) y contextos como _struct sobre puntero_ (`changetype`, sin `new` en el heap) — **`WASM Δ 0 B`** bajo carga sostenida.
- 🌐 **Multiplataforma**: Funciona en Node.js, Bun, Deno y Navegadores Web (Vite, Webpack, GitHub Pages).
- 🛡️ **Seguridad Crypto**:
  - **ChaCha20-Poly1305 / XChaCha20-Poly1305** (RFC 8439) como AEAD principal.
  - **Verificación constant-time** del tag: comparación por XOR + OR acumulativo sin _early-exit_.
  - **Limpieza de material sensible**: `wipe()` borra keystream, subclaves HChaCha20 y estado del Poly1305 al cerrar cada operación.
  - Correctitud validada contra vectores oficiales RFC 8439 (§A.3, §2.3.2/§2.4.2, §A.5), XChaCha20-Poly1305 y concurrencia en múltiples Worker Threads (`npm test`).
- 🔄 **Streaming Real**: Cifrado/auth de archivos de cualquier tamaño por chunks (`createEncryptStream` / `createDecryptStream`) — memoria plana de ~2.1 MB totales.

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

### 1. Inicializar la biblioteca (Single-Thread vs Multithread)

#### Opción A: Single-Thread (`dist/aead.wasm`)

```ts
import { AeadWasm } from "aead-wasm"

// Navegador / bundler (carga automática del singleton single-thread)
await AeadWasm.load()

// Node.js / Bun desde buffer binario explícito
import { readFileSync } from "node:fs"
const wasmBuffer = readFileSync("node_modules/aead-wasm/dist/aead.wasm")
await AeadWasm.fromBuffer(wasmBuffer)
```

#### Opción B: Multithread con memoria compartida (`dist/aead.mt.wasm`)

```ts
import { AeadWasm, ChaCha20Poly1305 } from "aead-wasm"

// Navegador / bundler (requiere cabeceras COOP/COEP para SharedArrayBuffer)
const mtWasm = await AeadWasm.loadThreaded("/aead.mt.wasm")

// O en Node.js (desde dist/aead.mt.wasm):
// import { readFileSync } from "node:fs"
// const mtWasm = await AeadWasm.fromBuffer(readFileSync("node_modules/aead-wasm/dist/aead.mt.wasm"))

// Comparte módulo + SharedArrayBuffer con Web Workers o node:worker_threads:
const wasmModule = mtWasm.getModule()!
const sharedMemory = mtWasm.getMemory() // WebAssembly.Memory({ initial: 34, maximum: 34, shared: true })
```

#### Ejemplo en Worker (`Web Worker` o `node:worker_threads`)

```ts
import { parentPort, workerData } from "node:worker_threads"
import { AeadWasm, ChaCha20Poly1305 } from "aead-wasm"

const { wasmModule, sharedMemory, key, nonce, payload } = workerData

// Instancia el worker apuntando a la MISMA SharedArrayBuffer del hilo principal.
// Gracias a --zeroFilledMemory y arena_lock(), NO sobreescribe ni corrompe datos activos.
await AeadWasm.fromModule(wasmModule, { env: { memory: sharedMemory } })

const sealed = ChaCha20Poly1305.encrypt(key, nonce, payload, "worker-aad")
parentPort!.postMessage(sealed)
```

> La carga se realiza **una sola vez** por hilo/worker. Después puedes usar `ChaCha20Poly1305` / `XChaCha20Poly1305` / `ChaCha20` / `XChaCha20` / `Poly1305` directamente.

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
import { AeadWasm, ChaCha20, XChaCha20, randomKey, randomNonce, randomXNonce } from "aead-wasm"

await AeadWasm.load()

const key = randomKey()
const nonce12 = randomNonce()   // 12 B para ChaCha20
const nonce24 = randomXNonce()  // 24 B para XChaCha20

const ct = ChaCha20.encrypt(key, nonce12, "datos a cifrar")
const pt = ChaCha20.decrypt(key, nonce12, ct) // == encrypt (XOR simétrico)

const xct = XChaCha20.encrypt(key, nonce24, "datos extendidos")
const xpt = XChaCha20.decrypt(key, nonce24, xct)
```

> ⚠️ **Advertencia**: ChaCha20 y XChaCha20 por sí solos **NO autentican** (son maleables). Para datos que deban ser confidenciales **y** auténticos, usa siempre el AEAD (`ChaCha20Poly1305` / `XChaCha20Poly1305`).

### 6. Poly1305 (MAC — RFC 8439)

Autenticación de mensajes (tag de 16 bytes), sin cifrado.

```ts
import { AeadWasm, Poly1305, randomKey } from "aead-wasm"

await AeadWasm.load()

const key = randomKey() // 32 bytes (r ‖ s)
const tag = Poly1305.mac(key, "mensaje a autenticar") // → Uint8Array(16)
```

### 7. Control del Lock de Memoria y Diagnósticos (`Arena`)

Todas las llamadas públicas adquieren y liberan el lock automáticamente (`withIoLock`). Si necesitas reservar exclusividad manualmente al operar sobre `WasmAllocator`:

```ts
const wasm = AeadWasm.getInstance()

console.log(wasm.getArenaStats())
// → { used: 0, capacity: 65536, locked: false, threaded: true | false }

if (wasm.tryLock()) {
  try {
    // Ninguna otra operación ni worker puede sobreescribir PARAM_IN / PARAM_OUT
    const alloc = wasm.getAllocator()
    alloc.writeInput(new Uint8Array([1, 2, 3, 4]), 0)
  } finally {
    wasm.unlock()
  }
}
```

### 8. Generación segura de claves y nonces (CSPRNG)

```ts
import { randomKey, randomNonce, randomXNonce, getRandomBytes, fillRandom } from "aead-wasm"

const key = randomKey() // 32 bytes (ChaCha20 / XChaCha20 / Poly1305)
const nonce = randomNonce() // 12 bytes (ChaCha20-Poly1305)
const xnonce = randomXNonce() // 24 bytes (XChaCha20-Poly1305)
const bytes = getRandomBytes(64) // N bytes aleatorios (crypto-safe)
fillRandom(existingBuffer) // rellena un buffer existente (zero-alloc)
```

> El CSPRNG es isomórfico (Node/Bun/Deno/Browser) y hace **fail-fast** si el entorno no expone Web Crypto (`getRandomValues`).

### 9. API de bajo nivel (`AeadWasm`) y Utilidades

```ts
import { AeadWasm, bytesToHex, hexToBytes, toUint8Array, concatBytes } from "aead-wasm"

const wasm = await AeadWasm.load() // o await AeadWasm.loadThreaded()

// Primitivas de streaming (ctxPtr opaco)
const ctx = wasm.aeadInitEncrypt("xchacha", key, nonce, aad)
const out = wasm.aeadUpdate(ctx, chunk)
const tag = wasm.aeadFinalEncrypt(ctx)
wasm.aeadFree(ctx) // abortar sin finalizar

// Primitivas directas
const ct = wasm.chacha20(key, nonce12, data, 0)
const mac = wasm.poly1305Mac(key, msg)

// Conversión
const hex = bytesToHex(new Uint8Array([0xde, 0xad, 0xbe, 0xef])) // "deadbeef"
const bytes = hexToBytes("deadbeef")
const utf8 = toUint8Array("texto")
const joined = concatBytes(a, b, c)
```

---

## 📊 Benchmarks de Rendimiento (Single-Thread vs Multithread)

Resultados ejecutados con `npm run bench` en **Node v22.23.2** (V8) sobre **linux x64 (4 vCPUs)** comparando ambos binarios:
- **Single-Thread (`dist/aead.wasm`)**: `8.1 KB`
- **Multithread (`dist/aead.mt.wasm`)**: `9.1 KB` (con `SharedArrayBuffer` y locks atómicos en `Arena`)

**One-shot — ops/s por tamaño de mensaje (ST vs MT):**

| Operación                    | 64 B (ST) | 64 B (MT) | 1 KB (ST) | 1 KB (MT) | 16 KB (ST) | 16 KB (MT) | 256 KB (ST) | 256 KB (MT) |
| ---------------------------- | --------: | --------: | --------: | --------: | ---------: | ---------: | ----------: | ----------: |
| Poly1305 (mac)               | 1,949,354 | 1,561,810 |   704,315 |   646,308 |     68,220 |     63,092 |       4,303 |       4,470 |
| ChaCha20 (encrypt)           | 1,353,523 | 1,140,193 |   205,754 |   181,067 |     16,668 |     16,385 |         911 |         999 |
| XChaCha20 (encrypt)          | 1,138,145 | 1,007,106 |   197,295 |   189,539 |     17,156 |     18,390 |       1,250 |         789 |
| ChaCha20-Poly1305 (encrypt)  |   470,640 |   450,859 |   149,567 |   150,011 |     15,976 |     12,751 |         849 |       1,038 |
| ChaCha20-Poly1305 (decrypt)  |   827,779 |   672,766 |   166,641 |   148,995 |     14,731 |     12,452 |         859 |       1,028 |
| XChaCha20-Poly1305 (encrypt) |   463,389 |   417,718 |   148,121 |   132,132 |     16,721 |     14,489 |         753 |         880 |
| XChaCha20-Poly1305 (decrypt) |   697,442 |   578,530 |   157,285 |   134,821 |     15,008 |     13,661 |         919 |         871 |

**One-shot — throughput (MB/s) por tamaño de mensaje (ST vs MT):**

| Operación                    | 64 B (ST / MT) | 1 KB (ST / MT) | 16 KB (ST / MT) | 256 KB (ST / MT) |
| ---------------------------- | -------------: | -------------: | --------------: | ---------------: |
| Poly1305 (mac)               |  124.8 / 100.0 |  721.2 / 661.8 | 1117.7 / 1033.7 |  1127.9 / 1171.7 |
| ChaCha20 (encrypt)           |    86.6 / 73.0 |  210.7 / 185.4 |   273.1 / 268.4 |    238.9 / 261.8 |
| XChaCha20 (encrypt)          |    72.8 / 64.5 |  202.0 / 194.1 |   281.1 / 301.3 |    327.7 / 206.8 |
| ChaCha20-Poly1305 (encrypt)  |    30.1 / 28.9 |  153.2 / 153.6 |   261.7 / 208.9 |    222.5 / 272.2 |
| ChaCha20-Poly1305 (decrypt)  |    53.0 / 43.1 |  170.6 / 152.6 |   241.4 / 204.0 |    225.3 / 269.5 |
| XChaCha20-Poly1305 (encrypt) |    29.7 / 26.7 |  151.7 / 135.3 |   274.0 / 237.4 |    197.3 / 230.8 |
| XChaCha20-Poly1305 (decrypt) |    44.6 / 37.0 |  161.1 / 138.1 |   245.9 / 223.8 |    241.0 / 228.4 |

**Streaming de archivos — AEAD encrypt (MB/s, 1 MB y 4 MB):**

| Operación          | 1 MB (ST / MT) | 4 MB (ST / MT) |
| ------------------ | -------------: | -------------: |
| ChaCha20-Poly1305  |  201.1 / 202.4 |  213.8 / 197.0 |
| XChaCha20-Poly1305 |  198.5 / 164.3 |  220.9 / 166.5 |

**Concurrencia MT — 4 Worker Threads compartiendo `SharedArrayBuffer` (payload 16 KB):**

| Primitiva                    | ops/s agregadas | MB/s agregados |
| ---------------------------- | --------------: | -------------: |
| Poly1305 (mac)               |          40,681 |          666.5 |
| ChaCha20 (encrypt)           |           7,632 |          125.0 |
| XChaCha20 (encrypt)          |          12,694 |          208.0 |
| ChaCha20-Poly1305 (encrypt)  |          10,882 |          178.3 |
| ChaCha20-Poly1305 (decrypt)  |           9,988 |          163.6 |
| XChaCha20-Poly1305 (encrypt) |           9,855 |          161.5 |
| XChaCha20-Poly1305 (decrypt) |           9,988 |          163.6 |

**Comparativa vs `node:crypto` (`chacha20-poly1305` nativo, Single-Thread):**

| Tamaño | `aead-wasm` ops/s | `node:crypto` ops/s | Speedup |
| ------ | ----------------: | ------------------: | ------: |
| 64 B   |           469,633 |             169,190 | **2.78x** |
| 1 KB   |           151,418 |             106,678 | **1.42x** |
| 16 KB  |            13,325 |              21,570 |   0.62x |
| 256 KB |               715 |               1,402 |   0.51x |

> En mensajes pequeños (64 B – 1 KB), `aead-wasm` supera a `node:crypto` hasta **2.78x** gracias al modelo zero-alloc en `Arena` (frente al coste de instanciar objetos OpenSSL por llamada). En modo MT con `SharedArrayBuffer`, múltiples workers comparten los 2.1 MB de memoria lineal con serialización atómica segura sobre `PARAM_IN`/`PARAM_OUT`; para máximo paralelismo CPU independiente por hilo, cada worker puede instanciar `aead.wasm` (ST).

**Validación ST + MT + Lock (`npm test`):**

| Suite                                | Cobertura                                                                           |
| ------------------------------------ | ----------------------------------------------------------------------------------- |
| Poly1305 — RFC 8439 §A.3             | 25 vectores oficiales en ST y MT                                                    |
| ChaCha20 / XChaCha20                 | vectores RFC / NaCl + round-trip en ST y MT                                         |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | vectores RFC 8439 §A.5 + tamper + streaming > 1 MB en ST y MT                     |
| Lock ST & MT (`Arena`)               | bloqueo sin sobreescritura en ST, contención atómica y 4 workers concurrentes en MT |

---

## 🏗️ Arquitectura Zero-Allocation & Arena

- **Clase estática `Arena` (`assembly/arena.ts`)**: 64 KB de trabajo + 1 MB de entrada (`PARAM_IN`) + 1 MB de salida (`PARAM_OUT`) reservados en tiempo de compilación (`memory.data`), con `Arena.save()` / `Arena.restore()` por operación.
- **Separación de locks (cero self-deadlock)**:
  - `IO_LOCK_PTR` (`arena_lock` / `arena_try_lock` / `arena_unlock`): protege `PARAM_IN` y `PARAM_OUT` en el puente JS↔WASM.
  - `ARENA_LOCK_PTR` (spinlock interno en MT): sincroniza el bump-pointer compartido (`ARENA_OFF_PTR`) dentro de `Arena.alloc/save/restore`.
- **Compilación condicional (`ASC_FEATURE_THREADS`)**: en `aead.wasm` (ST) el compilador elimina las operaciones atómicas y usa un global WASM; en `aead.mt.wasm` (MT) usa `atomic.cmpxchg`/`load`/`store` junto con `--zeroFilledMemory` para que los workers secundarios no reinicien la memoria compartida al instanciar.
- **Contextos como _struct sobre puntero_**: ChaCha20, XChaCha20, Poly1305 y AEAD operan vía `changetype` (sin `new`).
- **Verificación constant-time y wipe**: `secureEqual16` sin _early-exit_ y `wipe()` tras cada operación.

---

## 🛠️ Comandos de Desarrollo

```bash
# Compilar binarios WASM (ST + MT), paquete TS y Playground web
npm run build

# Compilar los binarios WASM individualmente
npm run asbuild:st       # Single-thread → dist/aead.wasm
npm run asbuild:mt       # Multithread   → dist/aead.mt.wasm
npm run asbuild          # Ambos binarios

# Verificación de tipos (paquete + playground)
npm run lint

# Verificación completa ST + MT + Worker Threads + Arena Lock
npm test

# Benchmark comparativo Single-Thread vs Multithread + Worker Threads + node:crypto
npm run bench

# Playground interactivo en desarrollo (http://localhost:3000)
npm run dev
```

---

## 📁 Estructura del Proyecto

```
aead-wasm/
├── assembly/                # Núcleo en AssemblyScript (→ WebAssembly)
│   ├── index.ts             # Exportaciones WASM (crypto + arena_lock/stats)
│   ├── arena.ts             # Clase estática Arena (bump allocator + lock ST/MT)
│   ├── chacha.ts            # ChaCha20 & XChaCha20 (HChaCha20, streaming, wipe)
│   ├── poly1305.ts          # Poly1305 (radix-2⁶, streaming, wipe)
│   └── aead.ts              # ChaCha20-Poly1305 & XChaCha20-Poly1305
├── src/                     # Wrapper en TypeScript
│   ├── index.ts             # Punto de entrada público
│   ├── aead-wasm.ts         # Cargador ST/MT (load, loadThreaded, fromModule) + Lock
│   ├── allocator.ts         # WasmAllocator (vista ArrayBuffer/SharedArrayBuffer)
│   ├── chacha20.ts          # ChaCha20 & XChaCha20
│   ├── poly1305.ts          # Poly1305
│   ├── aead.ts              # ChaCha20Poly1305 & XChaCha20Poly1305
│   ├── csprng.ts            # CSPRNG isomórfico
│   └── types.ts             # Contrato WASM, ArenaStats y utilidades
├── playground/              # Crypto Lab (SolidJS + TSX + CSS Modules)
├── public/favicon.svg       # Favicon SVG del Crypto Lab
├── .github/workflows/       # CI/CD automático hacia GitHub Pages
│   └── deploy.yml
├── test/
│   ├── verify-builds.ts     # Verificación ST + MT + Worker Threads + Arena Lock
│   ├── bench.ts             # Benchmark ST vs MT vs Worker Threads vs node:crypto
│   └── vectors/             # Vectores oficiales RFC 8439 y XChaCha20-Poly1305
├── dist/                    # Binarios (aead.wasm, aead.mt.wasm) + bundle JS/d.ts
├── asconfig.json            # Targets debug, release (ST) y release-mt (MT)
├── vite.config.ts           # Vite + plugin WASM + soporte VITE_BASE_PATH
├── package.json
└── LICENSE                  # Apache-2.0
```

---

## 📜 Licencia

[Apache License 2.0](./LICENSE) © **Edison Manrique**

> **Exención de responsabilidad:** este software se proporciona "tal cual" (AS IS), sin garantía de ningún tipo. Aunque ChaCha20-Poly1305, XChaCha20-Poly1305 y Poly1305 son estándares (RFC 8439), esta implementación no ha sido auditada formalmente y no debe emplearse en aplicaciones de seguridad crítica sin verificación independiente.
