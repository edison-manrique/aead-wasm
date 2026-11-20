import { For, Show } from "solid-js"
import {
  Lock,
  Shield,
  ShieldCheck,
  KeyRound,
  Waves,
  Sparkles,
  BookOpen,
  ShieldAlert,
  CheckCircle2,
  AlertCircle,
  Loader2
} from "lucide-solid"
import { ALGO_PAGES, type AlgoPageId, type AlgoPageMeta } from "../types/crypto"
import styles from "./Sidebar.module.css"

interface SidebarProps {
  activePage: AlgoPageId
  onSelectPage: (id: AlgoPageId) => void
  wasmStatus: "loading" | "ready" | "error"
}

function renderAlgoIcon(id: AlgoPageId) {
  switch (id) {
    case "chacha20-poly1305":
      return <ShieldCheck size={14} />
    case "xchacha20-poly1305":
      return <Shield size={14} />
    case "chacha20":
      return <Waves size={14} />
    case "xchacha20":
      return <Sparkles size={14} />
    case "poly1305":
      return <KeyRound size={14} />
    case "security":
      return <ShieldAlert size={14} />
    case "docs":
      return <BookOpen size={14} />
  }
}

export function Sidebar(props: SidebarProps) {
  const aeadPages = () => ALGO_PAGES.filter((p) => p.category === "AEAD")
  const cipherPages = () => ALGO_PAGES.filter((p) => p.category === "Stream Cipher")
  const macPages = () => ALGO_PAGES.filter((p) => p.category === "MAC")
  const docPages = () => ALGO_PAGES.filter((p) => p.category === "Docs")

  const renderItem = (page: AlgoPageMeta) => {
    const isActive = () => props.activePage === page.id
    return (
      <button
        type="button"
        class={`${styles.navItem} ${isActive() ? styles.navItemActive : ""}`}
        onClick={() => props.onSelectPage(page.id)}
        aria-current={isActive() ? "page" : undefined}
      >
        <span class={styles.navItemLeft}>
          <span class={styles.navIcon}>{renderAlgoIcon(page.id)}</span>
          <span class={styles.navLabel}>{page.name}</span>
        </span>
        <Show when={page.nonceBytes !== null || page.tagBytes !== null}>
          <span class={styles.navSpec}>
            {page.nonceBytes ? `${page.nonceBytes}B` : `${page.tagBytes}B`}
          </span>
        </Show>
      </button>
    )
  }

  return (
    <aside class={styles.sidebar} aria-label="Navegación de primitivas criptográficas">
      <div class={styles.brand}>
        <div class={styles.brandMark} aria-hidden="true">
          <Lock size={14} />
        </div>
        <span class={styles.brandText}>AEAD WASM</span>
      </div>

      <nav class={styles.navScroll}>
        <div class={styles.group}>
          <div class={styles.groupTitle}>Cifrado Autenticado</div>
          <For each={aeadPages()}>{renderItem}</For>
        </div>

        <div class={styles.group}>
          <div class={styles.groupTitle}>Cifradores de Flujo</div>
          <For each={cipherPages()}>{renderItem}</For>
        </div>

        <div class={styles.group}>
          <div class={styles.groupTitle}>Autenticación</div>
          <For each={macPages()}>{renderItem}</For>
        </div>

        <div class={styles.group}>
          <div class={styles.groupTitle}>Referencia</div>
          <For each={docPages()}>{renderItem}</For>
        </div>
      </nav>

      <div class={styles.sidebarFooter}>
        <Show
          when={props.wasmStatus === "ready"}
          fallback={
            <Show
              when={props.wasmStatus === "error"}
              fallback={
                <span class={styles.wasmState}>
                  <Loader2 size={13} />
                  <span>Cargando WASM</span>
                </span>
              }
            >
              <span class={`${styles.wasmState} ${styles.wasmError}`}>
                <AlertCircle size={13} />
                <span>Error WASM</span>
              </span>
            </Show>
          }
        >
          <span class={`${styles.wasmState} ${styles.wasmReady}`}>
            <CheckCircle2 size={13} />
            <span>WASM listo</span>
          </span>
        </Show>
        <span class={styles.wasmSize}>RFC 8439</span>
      </div>
    </aside>
  )
}
