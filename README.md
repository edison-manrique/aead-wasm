# 🔐 AEAD WASM

Biblioteca de cifrado autenticado (AEAD) ultra-rápida y de alto rendimiento compilada en WebAssembly (WASM) utilizando AssemblyScript y empaquetada con un wrapper TypeScript Zero-Allocation, disponible en variantes **Single-Thread** (`aead.wasm`) y **Multithread** (`aead.mt.wasm`).

Soporta **ChaCha20-Poly1305** y **XChaCha20-Poly1305** (RFC 8439), los cifradores de flujo **ChaCha20 / XChaCha20** y el MAC **Poly1305** —con **verificación de tags en tiempo constante** (a prueba de _timing attacks_), **streaming de archivos en tiempo real**, **cifrado in-place** y **lock exclusivo en `Arena`** contra sobreescrituras concurrentes— con **0 % de presión sobre el Garbage Collector (GC)**.

---

## 🚀 Características Principales

- ⚡ **Doble Compilación (ST & MT)**:
  - **Single-Thread (`dist/aead.wasm`, 8.3 KB)**: cero instrucciones atómicas, ideal para uso secuencial y entornos sin `SharedArrayBuffer`.
  - **Multithread (`dist/aead.mt.wasm`, 8.7 KB)**: compilado con `--enable threads --sharedMemory --importMemory --zeroFilledMemory` sobre `SharedArrayBuffer` (264 págs ≈ 16.5 MB) con **8 slots paralelos** (`PARAM_IN`/`PARAM_OUT` + Arena dedicados por slot) para escalado multi-core real entre Web Workers o `node:worker_threads`.
- 🔒 **Pool Multi-Slot + Lock en `Arena` (`assembly/arena.ts`)**:
  - Cada slot posee sus propias regiones `PARAM_IN[s]` / `PARAM_OUT[s]` y segmento de Arena (16 KB/slot). Un `Atomics.compareExchange` adquiere el slot una sola vez y el hot-path interno de `Arena` corre con **cero atómicos**.
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

// Comparte módulo + SharedArrayBuffer (264 págs, 8 slots paralelos) con Workers:
const wasmModule = mtWasm.getModule()!
const sharedMemory = mtWasm.getMemory() // WebAssembly.Memory({ initial: 264, maximum: 264, shared: true })
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
// → { used: 0, capacity: 16384 | 65536, locked: false, threaded: true | false, slots: 8 | 1 }

// Lock manual del Slot 0 (o lockSlot(s) / unlockSlot(s) en modo multi-slot MT):
if (wasm.tryLock()) {
  try {
    // Ninguna otra operación ni worker puede sobreescribir PARAM_IN[0] / PARAM_OUT[0]
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
- **Single-Thread (`dist/aead.wasm`)**: `8.3 KB` (1 slot, 34 págs)
- **Multithread (`dist/aead.mt.wasm`)**: `8.7 KB` (8 slots paralelos sin contención en `SharedArrayBuffer`, 264 págs)

**One-shot — ops/s por tamaño de mensaje (ST vs MT):**

| Operación                    | 64 B (ST) | 64 B (MT) | 1 KB (ST) | 1 KB (MT) | 16 KB (ST) | 16 KB (MT) | 256 KB (ST) | 256 KB (MT) |
| ---------------------------- | --------: | --------: | --------: | --------: | ---------: | ---------: | ----------: | ----------: |
| Poly1305 (mac)               | 1,928,135 | 1,640,805 |   717,544 |   646,885 |     70,474 |     64,640 |       4,613 |       4,288 |
| ChaCha20 (encrypt)           | 1,406,421 | 1,159,076 |   198,959 |   179,288 |     16,469 |     18,867 |         916 |       1,088 |
| XChaCha20 (encrypt)          | 1,190,573 | 1,028,661 |   201,981 |   187,932 |     20,752 |     19,883 |       1,318 |       1,190 |
| ChaCha20-Poly1305 (encrypt)  |   491,601 |   452,827 |   156,701 |   149,709 |     15,031 |     15,885 |         997 |         936 |
| ChaCha20-Poly1305 (decrypt)  |   842,222 |   686,439 |   164,117 |   152,879 |     14,859 |     15,215 |         926 |       1,010 |
| XChaCha20-Poly1305 (encrypt) |   470,144 |   454,928 |   152,009 |   141,870 |     14,138 |     13,882 |       1,007 |         913 |
| XChaCha20-Poly1305 (decrypt) |   749,348 |   619,591 |   152,103 |   135,327 |     12,855 |     14,179 |         929 |         917 |

**One-shot — throughput (MB/s) por tamaño de mensaje (ST vs MT):**

| Operación                    | 64 B (ST / MT) | 1 KB (ST / MT) | 16 KB (ST / MT) | 256 KB (ST / MT) |
| ---------------------------- | -------------: | -------------: | --------------: | ---------------: |
| Poly1305 (mac)               |  123.4 / 105.0 |  734.8 / 662.4 | 1154.6 / 1059.1 |  1209.3 / 1124.1 |
| ChaCha20 (encrypt)           |    90.0 / 74.2 |  203.7 / 183.6 |   269.8 / 309.1 |    240.2 / 285.2 |
| XChaCha20 (encrypt)          |    76.2 / 65.8 |  206.8 / 192.4 |   340.0 / 325.8 |    345.4 / 311.8 |
| ChaCha20-Poly1305 (encrypt)  |    31.5 / 29.0 |  160.5 / 153.3 |   246.3 / 260.3 |    261.5 / 245.3 |
| ChaCha20-Poly1305 (decrypt)  |    53.9 / 43.9 |  168.1 / 156.5 |   243.4 / 249.3 |    242.7 / 264.7 |
| XChaCha20-Poly1305 (encrypt) |    30.1 / 29.1 |  155.7 / 145.3 |   231.6 / 227.4 |    264.0 / 239.4 |
| XChaCha20-Poly1305 (decrypt) |    48.0 / 39.7 |  155.8 / 138.6 |   210.6 / 232.3 |    243.6 / 240.5 |

**Streaming de archivos — AEAD encrypt (MB/s, 1 MB y 4 MB):**

| Operación          | 1 MB (ST / MT) | 4 MB (ST / MT) |
| ------------------ | -------------: | -------------: |
| ChaCha20-Poly1305  |  181.4 / 196.6 |  234.6 / 184.3 |
| XChaCha20-Poly1305 |  245.7 / 212.9 |  226.9 / 204.0 |

**Concurrencia MT — 4 Worker Threads compartiendo `SharedArrayBuffer` (payload 16 KB):**

| Primitiva                    | ops/s agregadas | MB/s agregados | Escalado vs ST (1 hilo) |
| ---------------------------- | --------------: | -------------: | ----------------------: |
| Poly1305 (mac)               |         190,953 |     **3,128.6** |                 **2.71x** |
| ChaCha20 (encrypt)           |          35,114 |          575.3 |                 **2.13x** |
| XChaCha20 (encrypt)          |          52,948 |          867.5 |                 **2.55x** |
| ChaCha20-Poly1305 (encrypt)  |          40,189 |      **658.5** |                 **2.67x** |
| ChaCha20-Poly1305 (decrypt)  |          38,763 |          635.1 |                 **2.61x** |
| XChaCha20-Poly1305 (encrypt) |          35,483 |          581.4 |                 **2.51x** |
| XChaCha20-Poly1305 (decrypt) |          37,097 |          607.8 |                 **2.89x** |

**Comparativa vs `node:crypto` (`chacha20-poly1305` nativo, Single-Thread):**

| Tamaño | `aead-wasm` ops/s | `node:crypto` ops/s | Speedup |
| ------ | ----------------: | ------------------: | ------: |
| 64 B   |           527,583 |             166,420 | **3.17x** |
| 1 KB   |           159,022 |             102,003 | **1.56x** |
| 16 KB  |            16,354 |              48,632 |   0.34x |
| 256 KB |             1,046 |               2,527 |   0.41x |

> En mensajes pequeños (64 B – 1 KB), `aead-wasm` supera a `node:crypto` hasta **3.17x** gracias al modelo zero-alloc en `Arena`. En modo Multithread, el pool de **8 slots independientes** elimina la contención entre workers y permite escalar de **2.13x a 2.89x** sobre Single-Thread con 4 Worker Threads compartiendo la misma `SharedArrayBuffer` (**3,128.6 MB/s** en Poly1305 y **658.5 MB/s** en ChaCha20-Poly1305).

**Validación ST + MT + Lock (`npm test`):**

| Suite                                | Cobertura                                                                           |
| ------------------------------------ | ----------------------------------------------------------------------------------- |
| Poly1305 — RFC 8439 §A.3             | 25 vectores oficiales en ST y MT                                                    |
| ChaCha20 / XChaCha20                 | vectores RFC / NaCl + round-trip en ST y MT                                         |
| ChaCha20-Poly1305 / XChaCha20-Poly1305 | vectores RFC 8439 §A.5 + tamper + streaming > 1 MB en ST y MT                     |
| Lock ST & MT (`Arena`)               | bloqueo sin sobreescritura en ST, aislamiento de 8 slots, contención atómica y 4 workers concurrentes en MT |

---

## 🏗️ Arquitectura Zero-Allocation & Arena

- **Clase estática `Arena` (`assembly/arena.ts`)**:
  - **ST (`aead.wasm`, 34 págs)**: 64 KB de arena + 1 MB `PARAM_IN` + 1 MB `PARAM_OUT` reservados en compilación (`memory.data`), con cero instrucciones atómicas.
  - **MT (`aead.mt.wasm`, 264 págs)**: **8 slots paralelos** (`PARAM_IN[s]`, `PARAM_OUT[s]` y 16 KB de arena/slot). Cada instancia de worker mantiene `Arena.activeSlot` y `Arena.current` en globales thread-local WASM, por lo que `Arena.save()/alloc()/restore()` operan con **cero atómicos** dentro del hot-path.
- **Sincronización sin contención**: cada hilo adquiere su `preferredSlot` mediante un único `Atomics.compareExchange` en JS sobre `CTRL_BASE[slot]` (0 llamadas extra a WASM en one-shot) y solo hace spin-wait si los 8 slots están ocupados simultáneamente.
- **Compilación condicional (`ASC_FEATURE_THREADS`)**: en `aead.mt.wasm` se compila con `--zeroFilledMemory` para que los workers secundarios nunca sobreescriban la memoria compartida al instanciar.
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
