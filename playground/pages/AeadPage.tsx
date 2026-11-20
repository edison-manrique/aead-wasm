import { createSignal, Show } from "solid-js"
import {
  Lock,
  Unlock,
  ShieldAlert,
  Download,
  ArrowRightLeft,
  CheckCircle2,
  AlertCircle
} from "lucide-solid"
import {
  AeadVariant,
  ChaCha20Poly1305,
  XChaCha20Poly1305,
  bytesToHex,
  hexToBytes,
  randomKey,
  randomNonce,
  randomXNonce,
  TAG_BYTES
} from "@aead-wasm"
import type { AlgoPageMeta, FileProcessResult, InputMode } from "../types/crypto"
import {
  decryptFileAead,
  encryptFileAead,
  formatBytes,
  parseStrictHex,
  triggerFileDownload
} from "../utils/cryptoHelpers"
import { KeyNoncePanel } from "../components/KeyNoncePanel"
import { ModeSwitch } from "../components/ModeSwitch"
import { FileDropZone } from "../components/FileDropZone"
import { OutputBox } from "../components/OutputBox"
import styles from "../styles/PageShared.module.css"

interface AeadPageProps {
  variant: AeadVariant
  meta: AlgoPageMeta
  wasmReady: boolean
  registerRotateHandler: (fn: () => void) => void
}

export function AeadPage(props: AeadPageProps) {
  const nonceBytes = () => (props.variant === "chacha" ? 12 : 24)
  const genNonceHex = () => bytesToHex(props.variant === "chacha" ? randomNonce() : randomXNonce())

  const [mode, setMode] = createSignal<InputMode>("text")
  const [keyHex, setKeyHex] = createSignal(bytesToHex(randomKey()))
  const [nonceHex, setNonceHex] = createSignal(genNonceHex())
  const [aadText, setAadText] = createSignal("header-metadata-v1")

  // Modo texto
  const [plaintext, setPlaintext] = createSignal(
    props.variant === "chacha"
      ? "Mensaje autenticado con ChaCha20-Poly1305 en WebAssembly."
      : "Mensaje autenticado con XChaCha20-Poly1305 y nonce extendido de 192 bits."
  )
  const [combinedInputHex, setCombinedInputHex] = createSignal("")
  const [sealedHex, setSealedHex] = createSignal<string | null>(null)
  const [tagHex, setTagHex] = createSignal<string | null>(null)
  const [sealedMeta, setSealedMeta] = createSignal<string | undefined>(undefined)
  const [sealStatus, setSealStatus] = createSignal<"idle" | "ok" | "err">("idle")

  const [openedText, setOpenedText] = createSignal<string | null>(null)
  const [openedMeta, setOpenedMeta] = createSignal<string | undefined>(undefined)
  const [openStatus, setOpenStatus] = createSignal<"idle" | "ok" | "err">("idle")
  const [tamperFeedback, setTamperFeedback] = createSignal<{ ok: boolean; msg: string } | null>(null)

  // Modo archivo
  const [selectedFile, setSelectedFile] = createSignal<File | null>(null)
  const [fileBusy, setFileBusy] = createSignal(false)
  const [fileProgress, setFileProgress] = createSignal<number | null>(null)
  const [fileResult, setFileResult] = createSignal<FileProcessResult | null>(null)
  const [fileError, setFileError] = createSignal<string | null>(null)
  const [fileActionType, setFileActionType] = createSignal<"encrypt" | "decrypt" | null>(null)

  const rotateCredentials = () => {
    setKeyHex(bytesToHex(randomKey()))
    setNonceHex(genNonceHex())
  }

  props.registerRotateHandler(rotateCredentials)

  const getImpl = () => (props.variant === "chacha" ? ChaCha20Poly1305 : XChaCha20Poly1305)

  const handleSealText = () => {
    if (!props.wasmReady) return
    setTamperFeedback(null)
    try {
      const started = performance.now()
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const aad = aadText().length > 0 ? aadText() : null
      const sealed = getImpl().encrypt(key, nonce, plaintext(), aad)
      const elapsed = performance.now() - started

      const hex = bytesToHex(sealed)
      const tag = bytesToHex(sealed.subarray(sealed.length - TAG_BYTES))
      setSealedHex(hex)
      setTagHex(tag)
      setCombinedInputHex(hex)
      setSealedMeta(`${sealed.length} B · ${elapsed.toFixed(2)} ms`)
      setSealStatus("ok")
      setOpenedText(null)
      setOpenStatus("idle")
    } catch (err) {
      setSealedHex(err instanceof Error ? err.message : String(err))
      setTagHex(null)
      setSealedMeta(undefined)
      setSealStatus("err")
    }
  }

  const handleOpenText = () => {
    if (!props.wasmReady) return
    setTamperFeedback(null)
    try {
      const started = performance.now()
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const cleanHex = combinedInputHex().trim().replace(/\s+/g, "")
      if (!cleanHex || cleanHex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(cleanHex)) {
        throw new Error("El ciphertext combinado debe ser una cadena hexadecimal válida.")
      }
      const combined = hexToBytes(cleanHex)
      const aad = aadText().length > 0 ? aadText() : null
      const opened = getImpl().decrypt(key, nonce, combined, aad)
      const elapsed = performance.now() - started

      if (opened === null) {
        setOpenedText("Tag inválido: el mensaje fue alterado o las credenciales/AAD no coinciden.")
        setOpenedMeta(`${elapsed.toFixed(2)} ms`)
        setOpenStatus("err")
        return
      }

      setOpenedText(new TextDecoder().decode(opened))
      setOpenedMeta(`${opened.length} B verificados · ${elapsed.toFixed(2)} ms`)
      setOpenStatus("ok")
    } catch (err) {
      setOpenedText(err instanceof Error ? err.message : String(err))
      setOpenedMeta(undefined)
      setOpenStatus("err")
    }
  }

  const handleTamperTest = () => {
    if (!props.wasmReady) return
    try {
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const cleanHex = combinedInputHex().trim().replace(/\s+/g, "")
      if (!cleanHex) {
        setTamperFeedback({ ok: false, msg: "Primero cifra un mensaje para probar la detección de alteraciones." })
        return
      }
      const tampered = hexToBytes(cleanHex)
      if (tampered.length === 0) return
      tampered[0] ^= 0xff
      const aad = aadText().length > 0 ? aadText() : null
      const res = getImpl().decrypt(key, nonce, tampered, aad)
      if (res === null) {
        setTamperFeedback({
          ok: true,
          msg: "Prueba de alteración superada: al invertir 1 byte del ciphertext, Poly1305 rechazó el paquete (decrypt = null)."
        })
      } else {
        setTamperFeedback({ ok: false, msg: "Error inesperado: el paquete alterado fue aceptado." })
      }
    } catch (err) {
      setTamperFeedback({ ok: false, msg: err instanceof Error ? err.message : String(err) })
    }
  }

  const handleEncryptFile = async () => {
    const file = selectedFile()
    if (!props.wasmReady || !file || fileBusy()) return
    setFileError(null)
    setFileResult(null)
    setFileBusy(true)
    setFileProgress(0)
    setFileActionType("encrypt")
    try {
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const aad = aadText().length > 0 ? new TextEncoder().encode(aadText()) : null
      const result = await encryptFileAead(props.variant, file, key, nonce, aad, (r) => setFileProgress(r))
      setFileResult(result)
    } catch (err) {
      setFileError(err instanceof Error ? err.message : String(err))
    } finally {
      setFileBusy(false)
    }
  }

  const handleDecryptFile = async () => {
    const file = selectedFile()
    if (!props.wasmReady || !file || fileBusy()) return
    setFileError(null)
    setFileResult(null)
    setFileBusy(true)
    setFileProgress(0)
    setFileActionType("decrypt")
    try {
      const key = parseStrictHex(keyHex(), 32, "Clave")
      const nonce = parseStrictHex(nonceHex(), nonceBytes(), "Nonce")
      const aad = aadText().length > 0 ? new TextEncoder().encode(aadText()) : null
      const result = await decryptFileAead(props.variant, file, key, nonce, aad, (r) => setFileProgress(r))
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
    const nextFile = new File([copy.buffer], res.fileName, { type: "application/octet-stream" })
    setSelectedFile(nextFile)
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
          <h2 class={styles.sectionTitle}>Credenciales y datos asociados</h2>
          <span class={styles.sectionMeta}>
            Key 32 B · Nonce {nonceBytes()} B · Tag 16 B
          </span>
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

        <div class={styles.field}>
          <div class={styles.labelRow}>
            <label class={styles.label} for={`aad-${props.variant}`}>
              AAD — Datos asociados autenticados (opcional, texto UTF-8)
            </label>
            <span class={styles.hint}>{new TextEncoder().encode(aadText()).length} bytes</span>
          </div>
          <input
            id={`aad-${props.variant}`}
            type="text"
            class={styles.input}
            value={aadText()}
            onInput={(e) => setAadText(e.currentTarget.value)}
            placeholder="Cabecera o metadatos autenticados sin cifrar..."
          />
        </div>
      </section>

      <Show
        when={mode() === "text"}
        fallback={
          <section class={styles.section}>
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Cifrado y descifrado de archivos por streaming</h2>
              <span class={styles.sectionMeta}>Chunks de 1 MB · Formato ct ‖ tag</span>
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
              hint="Soporta archivos de cualquier tamaño mediante createEncryptStream / createDecryptStream"
            />

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady || !selectedFile() || fileBusy()}
                onClick={handleEncryptFile}
              >
                <Lock size={14} />
                <span>Cifrar archivo</span>
              </button>
              <button
                type="button"
                class={styles.btnSecondary}
                disabled={!props.wasmReady || !selectedFile() || fileBusy()}
                onClick={handleDecryptFile}
              >
                <Unlock size={14} />
                <span>Descifrar y verificar</span>
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
                    <span>
                      {fileActionType() === "encrypt"
                        ? "Archivo cifrado y autenticado correctamente."
                        : "Tag Poly1305 verificado. Archivo descifrado con integridad íntegra."}
                    </span>
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

                  <Show when={res().tagHex}>
                    {(tag) => (
                      <OutputBox
                        label="Tag Poly1305 (16 bytes)"
                        value={tag()}
                        status="ok"
                        meta="Verificación constant-time"
                      />
                    )}
                  </Show>

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
              <h2 class={styles.sectionTitle}>Cifrar (Seal)</h2>
              <span class={styles.sectionMeta}>Plaintext → ct ‖ tag</span>
            </div>

            <div class={styles.field}>
              <div class={styles.labelRow}>
                <label class={styles.label} for={`pt-${props.variant}`}>
                  Texto plano (UTF-8)
                </label>
                <span class={styles.hint}>{new TextEncoder().encode(plaintext()).length} bytes</span>
              </div>
              <textarea
                id={`pt-${props.variant}`}
                class={`${styles.textarea} ${styles.textareaSans}`}
                value={plaintext()}
                onInput={(e) => setPlaintext(e.currentTarget.value)}
                placeholder="Escribe el texto a cifrar..."
              />
            </div>

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady}
                onClick={handleSealText}
              >
                <Lock size={14} />
                <span>Cifrar y autenticar</span>
              </button>
            </div>

            <OutputBox
              label="Salida combinada (ciphertext ‖ tag)"
              value={sealedHex()}
              status={sealStatus()}
              meta={sealedMeta()}
              placeholder="Pulsa Cifrar y autenticar para generar el resultado en hex"
            />

            <Show when={tagHex()}>
              {(tag) => <OutputBox label="Tag de autenticación (16 B)" value={tag()} status="ok" />}
            </Show>
          </section>

          <section class={styles.section}>
            <div class={styles.sectionHeader}>
              <h2 class={styles.sectionTitle}>Descifrar y verificar (Open)</h2>
              <span class={styles.sectionMeta}>ct ‖ tag → Plaintext</span>
            </div>

            <div class={styles.field}>
              <div class={styles.labelRow}>
                <label class={styles.label} for={`ct-${props.variant}`}>
                  Ciphertext combinado (hex)
                </label>
                <span class={styles.hint}>
                  {Math.floor(combinedInputHex().trim().replace(/\s+/g, "").length / 2)} bytes
                </span>
              </div>
              <textarea
                id={`ct-${props.variant}`}
                class={styles.textarea}
                value={combinedInputHex()}
                onInput={(e) => setCombinedInputHex(e.currentTarget.value)}
                placeholder="Pega aquí el resultado hex combinado (ct ‖ tag)..."
                spellcheck={false}
              />
            </div>

            <div class={styles.btnRow}>
              <button
                type="button"
                class={styles.btnPrimary}
                disabled={!props.wasmReady}
                onClick={handleOpenText}
              >
                <Unlock size={14} />
                <span>Verificar y descifrar</span>
              </button>
              <button
                type="button"
                class={styles.btnSecondary}
                disabled={!props.wasmReady || !combinedInputHex().trim()}
                onClick={handleTamperTest}
              >
                <ShieldAlert size={14} />
                <span>Simular alteración</span>
              </button>
            </div>

            <OutputBox
              label="Texto descifrado"
              value={openedText()}
              status={openStatus()}
              meta={openedMeta()}
              placeholder="El texto solo se mostrará si el tag Poly1305 es válido"
            />

            <Show when={tamperFeedback()}>
              {(fb) => (
                <div class={`${styles.notice} ${fb().ok ? styles.noticeOk : styles.noticeErr}`}>
                  <Show when={fb().ok} fallback={<AlertCircle size={16} class={styles.noticeIcon} />}>
                    <CheckCircle2 size={16} class={styles.noticeIcon} />
                  </Show>
                  <span>{fb().msg}</span>
                </div>
              )}
            </Show>
          </section>
        </div>
      </Show>
    </div>
  )
}
