import { defineConfig, type Plugin } from "vite"
import solidPlugin from "vite-plugin-solid"
import fs from "node:fs"
import path from "node:path"

/**
 * Sirve `dist/aead.wasm` en `/aead.wasm` durante el desarrollo y lo emite en
 * la raíz del bundle (`dist-app/aead.wasm`) al compilar para producción.
 */
function aeadWasmPlugin(): Plugin {
  const wasmSource = path.resolve(process.cwd(), "dist", "aead.wasm")

  return {
    name: "aead-wasm-asset",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        if (req.url === "/aead.wasm" || req.url === "/dist/aead.wasm") {
          if (!fs.existsSync(wasmSource)) {
            res.statusCode = 404
            res.end("aead.wasm not built yet. Run npm run asbuild.")
            return
          }
          res.setHeader("Content-Type", "application/wasm")
          fs.createReadStream(wasmSource).pipe(res)
          return
        }
        next()
      })
    },
    generateBundle() {
      if (fs.existsSync(wasmSource)) {
        this.emitFile({
          type: "asset",
          fileName: "aead.wasm",
          source: fs.readFileSync(wasmSource)
        })
      }
    }
  }
}

export default defineConfig({
  plugins: [solidPlugin(), aeadWasmPlugin()],
  resolve: {
    alias: {
      "@aead-wasm": path.resolve(process.cwd(), "src/index.ts")
    }
  },
  css: {
    modules: {
      localsConvention: "camelCaseOnly"
    }
  },
  server: {
    host: "0.0.0.0",
    port: 3000
  },
  build: {
    outDir: "dist-app",
    emptyOutDir: true,
    target: "esnext"
  }
})
