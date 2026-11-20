import { createMemo, createSignal, onCleanup, onMount, Show } from "solid-js"
import { AeadWasm } from "@aead-wasm"
import { ALGO_PAGES, type AlgoPageId } from "./types/crypto"
import { Sidebar } from "./components/Sidebar"
import { Header } from "./components/Header"
import { AeadPage } from "./pages/AeadPage"
import { StreamCipherPage } from "./pages/StreamCipherPage"
import { Poly1305Page } from "./pages/Poly1305Page"
import { SecurityPage } from "./pages/SecurityPage"
import { DocsPage } from "./pages/DocsPage"
import styles from "./App.module.css"

function resolveInitialPage(): AlgoPageId {
  const hash = window.location.hash.replace(/^#/, "") as AlgoPageId
  if (ALGO_PAGES.some((p) => p.id === hash)) {
    return hash
  }
  return "chacha20-poly1305"
}

export function App() {
  const [activePage, setActivePage] = createSignal<AlgoPageId>(resolveInitialPage())
  const [wasmStatus, setWasmStatus] = createSignal<"loading" | "ready" | "error">("loading")
  const [wasmError, setWasmError] = createSignal<string | null>(null)

  const rotateHandlers: Partial<Record<AlgoPageId, () => void>> = {}

  const activeMeta = createMemo(
    () => ALGO_PAGES.find((p) => p.id === activePage()) ?? ALGO_PAGES[0]
  )

  const selectPage = (id: AlgoPageId) => {
    setActivePage(id)
    if (window.location.hash !== `#${id}`) {
      window.history.replaceState(null, "", `#${id}`)
    }
  }

  onMount(async () => {
    const onHashChange = () => {
      const next = window.location.hash.replace(/^#/, "") as AlgoPageId
      if (ALGO_PAGES.some((p) => p.id === next)) {
        setActivePage(next)
      }
    }
    window.addEventListener("hashchange", onHashChange)
    onCleanup(() => window.removeEventListener("hashchange", onHashChange))

    const wasmUrl = `${import.meta.env.BASE_URL}aead.wasm`
    try {
      await AeadWasm.load(wasmUrl)
      setWasmStatus("ready")
    } catch (err) {
      setWasmStatus("error")
      setWasmError(err instanceof Error ? err.message : String(err))
    }
  })

  const metaById = (id: AlgoPageId) => ALGO_PAGES.find((p) => p.id === id)!

  return (
    <div class={styles.shell}>
      <Sidebar
        activePage={activePage()}
        onSelectPage={selectPage}
        wasmStatus={wasmStatus()}
      />

      <div class={styles.mainColumn}>
        <Header
          page={activeMeta()}
          onRegenerateKeys={() => rotateHandlers[activePage()]?.()}
          onGoToLab={() => selectPage("chacha20-poly1305")}
        />

        <main class={styles.viewport}>
          <Show when={wasmError()}>
            {(err) => (
              <div class={styles.errorBanner}>
                No se pudo inicializar el módulo WebAssembly ({`${import.meta.env.BASE_URL}aead.wasm`}): {err()}
              </div>
            )}
          </Show>

          <div class={activePage() === "chacha20-poly1305" ? styles.pageSlot : styles.pageSlotHidden}>
            <AeadPage
              variant="chacha"
              meta={metaById("chacha20-poly1305")}
              wasmReady={wasmStatus() === "ready"}
              registerRotateHandler={(fn) => {
                rotateHandlers["chacha20-poly1305"] = fn
              }}
            />
          </div>

          <div class={activePage() === "xchacha20-poly1305" ? styles.pageSlot : styles.pageSlotHidden}>
            <AeadPage
              variant="xchacha"
              meta={metaById("xchacha20-poly1305")}
              wasmReady={wasmStatus() === "ready"}
              registerRotateHandler={(fn) => {
                rotateHandlers["xchacha20-poly1305"] = fn
              }}
            />
          </div>

          <div class={activePage() === "chacha20" ? styles.pageSlot : styles.pageSlotHidden}>
            <StreamCipherPage
              variant="chacha"
              meta={metaById("chacha20")}
              wasmReady={wasmStatus() === "ready"}
              registerRotateHandler={(fn) => {
                rotateHandlers["chacha20"] = fn
              }}
            />
          </div>

          <div class={activePage() === "xchacha20" ? styles.pageSlot : styles.pageSlotHidden}>
            <StreamCipherPage
              variant="xchacha"
              meta={metaById("xchacha20")}
              wasmReady={wasmStatus() === "ready"}
              registerRotateHandler={(fn) => {
                rotateHandlers["xchacha20"] = fn
              }}
            />
          </div>

          <div class={activePage() === "poly1305" ? styles.pageSlot : styles.pageSlotHidden}>
            <Poly1305Page
              meta={metaById("poly1305")}
              wasmReady={wasmStatus() === "ready"}
              registerRotateHandler={(fn) => {
                rotateHandlers["poly1305"] = fn
              }}
            />
          </div>

          <div class={activePage() === "security" ? styles.pageSlot : styles.pageSlotHidden}>
            <SecurityPage meta={metaById("security")} />
          </div>

          <div class={activePage() === "docs" ? styles.pageSlot : styles.pageSlotHidden}>
            <DocsPage meta={metaById("docs")} />
          </div>
        </main>
      </div>
    </div>
  )
}
