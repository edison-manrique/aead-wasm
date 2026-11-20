import { createSignal, Show } from "solid-js"
import { Lock, Unlock, Download, ArrowRightLeft, CheckCircle2, AlertCircle } from "lucide-solid"
import { ChaCha20, XChaCha20, bytesToHex, hexToBytes, randomKey, randomNonce, randomXNonce } from "@aead-wasm"
import type { AlgoPageMeta, FileProcessResult, InputMode } from "../types/crypto"
import { formatBytes, parseStrictHex, processFileStreamCipher, triggerFileDownload } from "../utils/cryptoHelpers"
import { KeyNoncePanel } from "../components/KeyNoncePanel"
import { ModeSwitch } from "../components/ModeSwitch"
import { FileDropZone } from "../components/FileDropZone"
import { OutputBox } from "../components/OutputBox"
import styles from "../styles/PageShared.module.css"

interface StreamCipherPageProps {
  variant: "chacha" | "xchacha"
  meta: AlgoPageMeta
  wasmReady: boolean
  registerRotateHandler: (fn: () => void) => void
}

export function StreamCipherPage(props: StreamCipherPageProps) {
  const nonceBytes = () => (props.variant === "chacha" ? 12 : 24)
  const genNonceHex = () => bytesToHex(props.variant === "chacha" ? randomNonce() : randomXNonce())

  const [mode, setMode] = createSignal<InputMode>("text")
  const [keyHex, setKeyHex] = createSignal(bytesToHex(randomKey()))
  const [nonceHex, setNonceHex] = createSignal(genNonceHex())
  const [counter, setCounter] = createSignal(0)

  // Modo texto
  const [plaintext, setPlaintext] = createSignal(
    props.variant === "chacha"
      ? "Cifrado de flujo ChaCha20 por XOR con keystream de 64 bytes."
      : "Cifrado de flujo XChaCha20 con subclave derivada vía HChaCha20."
  )
  const [cipherInputHex, setCipherInputHex] = createSignal("")
  const [cipherOutputHex, setCipherOutputHex] = createSignal<string | null>(null)
  const [cipherMeta, setCipherMeta] = createSignal<string | undefined>(undefined)
  const [cipherStatus, setCipherStatus] = createSignal<"idle" | "ok" | "err">("idle")

  const [decryptedText, setDecryptedText] = createSignal<string | null>(null)
  const [decryptedMeta, setDecryptedMeta] = createSignal<string | undefined>(undefined)
  const [decryptedStatus, setDecryptedStatus] = createSignal<"idle" | "ok" | "err">("idle")

  // Modo archivo
  const [selectedFile, setSelectedFile] = createSignal<File | null>(null)
  const [fileBusy, setFileBusy] = createSignal(false)
  const [fileProgress, setFileProgress] = createSignal<number | null>(null)
  const [fileResult, setFileResult] = createSignal<FileProcessResult | null>(null)
  const [fileError, setFileError] = createSignal<string | null>(null)

  const rotateCredentials = () => {
    setKeyHex(bytesToHex(randomKey()))
    setNonceHex(genNonceHex())
  }

  props.registerRotateHandler(rotateCredentials)

  const getImpl = () => (props.variant === "chacha" ? ChaCha20 : XChaCha20)

  const parseCounter = () => {
    const c = Number(counter())
    if (!Number.isInteger(c) || c < 0 || c > 0xffffffff) {
      throw new Error("El contador inicial debe ser un entero entre 0 y 4294967295.")
    }
    return c
  }

  const handleEncryptText = () => {
    if (!props.wasmReady) return
    try {
      const started = performance.now()
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const ctr = parseCounter()
      const ct = getImpl().encrypt(key, nonce, plaintext(), ctr)
      const elapsed = performance.now() - started

      const hex = bytesToHex(ct)
      setCipherOutputHex(hex)
      setCipherInputHex(hex)
      setCipherMeta(`${ct.length} B · counter ${ctr} · ${elapsed.toFixed(2)} ms`)
      setCipherStatus("ok")
      setDecryptedText(null)
      setDecryptedStatus("idle")
    } catch (err) {
      setCipherOutputHex(err instanceof Error ? err.message : String(err))
      setCipherMeta(undefined)
      setCipherStatus("err")
    }
  }

  const handleDecryptText = () => {
    if (!props.wasmReady) return
    try {
      const started = performance.now()
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const ctr = parseCounter()
      const cleanHex = cipherInputHex().trim().replace(/\s+/g, "")
      if (!cleanHex || cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
        throw new Error("El ciphertext debe ser una cadena hexadecimal válida.")
      }
      const pt = getImpl().decrypt(key, nonce, hexToBytes(cleanHex), ctr)
      const elapsed = performance.now() - started

      setDecryptedText(new TextDecoder().decode(pt))
      setDecryptedMeta(`${pt.length} B · counter ${ctr} · ${elapsed.toFixed(2)} ms`)
      setDecryptedStatus("ok")
    } catch (err) {
      setDecryptedText(err instanceof Error ? err.message : String(err))
      setDecryptedMeta(undefined)
      setDecryptedStatus("err")
    }
  }

  const handleProcessFile = async (op: "encrypt" | "decrypt") => {
    const file = selectedFile()
    if (!props.wasmReady || !file || fileBusy()) return
    setFileError(null)
    setFileResult(null)
    setFileBusy(true)
    setFileProgress(0)
    try {
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const ctr = parseCounter()
      const result = await processFileStreamCipher(props.variant, op, file, key, nonce, ctr, (r) =>
        setFileProgress(r)
      )
      setFileResult(result)
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err))
    } finally {
      setFileBusy(false)
    }
  }

  const handleLoadResultAsInput = () => {
    const res = fileResult()
    if (!res) return
    const copy = new Uint8Array(res.bytes.byteLength)
    copy.set(res.bytes)
    setSelectedFile(new File([copy.buffer], res.fileName, { type: "application/octet-stream" }))
    setFileResult(null)
    setFileProgress(null)
    setFileError(null)
  }

  return (
    <div class={styles.page}>
      <div class={styles.introRow}>
        <p class={styles.description}>{props.meta.description}</p>
        <ModeSwitch mode={mode()} onChange={setMode} />
      </div>

      <section class={styles.section}>
        <div class={styles.sectionHeader}>
          <h2 class={styles.sectionTitle}>Parámetros del cifrador</h2>
          <span class={styles.sectionMeta}>Key 32 B · Nonce {nonceBytes()} B · Bloque 64 B</span>
        </div>

        <KeyNoncePanel
          keyHex={keyHex()}
          onKeyChange={setKeyHex}
          onGenerateKey={() => setKeyHex(bytesToHex(randomKey()))}
          nonceHex={nonceHex()}
          nonceBytes={nonceBytes()}
          onNonceChange={setNonceHex}
          onGenerateNonce={() => setNonceHex(genNonceHex())}
        />

        <div class={styles.inlineGrid}>
          <div class={styles.field}>
            <label class={styles.label} for={`ctr-${props.variant}`}>
              Contador inicial de bloque (32-bit counter)
            </label>
            <input
              id={`ctr-${props.variant}`}
              type="number"
              min={0}
              max={4294967295}
              class={styles.input}
              value={counter()}
              onInput={(e) => setCounter(Number(e.currentTarget.value) || 0)}
            />
          </div>
          <button type="button" class={styles.btnSecondary} onClick={() => setCounter(0)}>
            Reiniciar contador a 0
          </button>
        </div>
      </section>

      <Show
        when={mode() === "text"}
        fallback={
          <section class={styles.section}>
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Cifrado de archivos por bloques (XOR simétrico)</h2>
              <span class={styles.sectionMeta}>Chunks alineados a 64 B (512 KB)</span>
            </div>

            <FileDropZone
              file={selectedFile()}
              onSelectFile={(f) => {
                setSelectedFile(f)
                setFileResult(null)
                setFileProgress(null)
                setFileError(null)
              }}
              progress={fileProgress()}
              hint="Avanza automáticamente el block counter entre chunks de 512 KB para archivos de cualquier tamaño"
            />

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady || !selectedFile() || fileBusy()}
                onClick={() => handleProcessFile("encrypt")}
              >
                <Lock size={14} />
                <span>Cifrar archivo</span>
              </button>
              <button
                type="button"
                class={styles.btnSecondary}
                disabled={!props.wasmReady || !selectedFile() || fileBusy()}
                onClick={() => handleProcessFile("decrypt")}
              >
                <Unlock size={14} />
                <span>Descifrar archivo</span>
              </button>
            </div>

            <Show when={fileError()}>
              {(err) => (
                <div class={`${styles.notice} ${styles.noticeErr}`}>
                  <AlertCircle size={16} class={styles.noticeIcon} />
                  <span>{err()}</span>
                </div>
              )}
            </Show>

            <Show when={fileResult()}>
              {(res) => (
                <>
                  <div class={`${styles.notice} ${styles.noticeOk}`}>
                    <CheckCircle2 size={16} class={styles.noticeIcon} />
                    <span>Operación de flujo completada correctamente.</span>
                  </div>

                  <div class={styles.statsRow}>
                    <span>Salida: {res().fileName}</span>
                    <span class={styles.statSep}>·</span>
                    <span>Tamaño: {formatBytes(res().bytes.length)}</span>
                    <span class={styles.statSep}>·</span>
                    <span>Tiempo: {res().elapsedMs.toFixed(2)} ms</span>
                    <span class={styles.statSep}>·</span>
                    <span>Rendimiento: {res().throughputMBs.toFixed(1)} MB/s</span>
                  </div>

                  <div class={styles.btnRow}>
                    <button
                      type="button"
                      class={styles.btnSuccess}
                      onClick={() => triggerFileDownload(res().bytes, res().fileName)}
                    >
                      <Download size={14} />
                      <span>Descargar {res().fileName}</span>
                    </button>
                    <button type="button" class={styles.btnSecondary} onClick={handleLoadResultAsInput}>
                      <ArrowRightLeft size={14} />
                      <span>Usar como archivo de entrada</span>
                    </button>
                  </div>
                </>
              )}
            </Show>
          </section>
        }
      >
        <div class={styles.twoCol}>
          <section class={styles.section}>
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Cifrar flujo</h2>
              <span class={styles.sectionMeta}>Plaintext ⊕ Keystream</span>
            </div>

            <div class={styles.field}>
              <div class={styles.labelRow}>
                <label class={styles.label} for={`sc-pt-${props.variant}`}>
                  Plaintext (UTF-8)
                </label>
                <span class={styles.hint}>{new TextEncoder().encode(plaintext()).length} bytes</span>
              </div>
              <textarea
                id={`sc-pt-${props.variant}`}
                class={`${styles.textarea} ${styles.textareaSans}`}
                value={plaintext()}
                onInput={(e) => setPlaintext(e.currentTarget.value)}
                placeholder="Texto a cifrar..."
              />
            </div>

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady}
                onClick={handleEncryptText}
              >
                <Lock size={14} />
                <span>Cifrar texto</span>
              </button>
            </div>

            <OutputBox
              label="Ciphertext (hex)"
              value={cipherOutputHex()}
              status={cipherStatus()}
              meta={cipherMeta()}
              placeholder="El resultado hexadecimal aparecerá aquí"
            />
          </section>

          <section class={styles.section}>
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Descifrar flujo</h2>
              <span class={styles.sectionMeta}>Ciphertext ⊕ Keystream</span>
            </div>

            <div class={styles.field}>
              <div class={styles.labelRow}>
                <label class={styles.label} for={`sc-ct-${props.variant}`}>
                  Ciphertext (hex)
                </label>
                <span class={styles.hint}>
                  {Math.floor(cipherInputHex().trim().replace(/\s+/g, "").length / 2)} bytes
                </span>
              </div>
              <textarea
                id={`sc-ct-${props.variant}`}
                class={styles.textarea}
                value={cipherInputHex()}
                onInput={(e) => setCipherInputHex(e.currentTarget.value)}
                placeholder="Pega el ciphertext hexadecimal..."
                spellcheck={false}
              />
            </div>

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady}
                onClick={handleDecryptText}
              >
                <Unlock size={14} />
                <span>Descifrar hex</span>
              </button>
            </div>

            <OutputBox
              label="Texto descifrado"
              value={decryptedText()}
              status={decryptedStatus()}
              meta={decryptedMeta()}
              placeholder="Usa la misma clave, nonce y counter para recuperar el texto"
            />
          </section>
        </div>
      </Show>
    </div>
  )
}
