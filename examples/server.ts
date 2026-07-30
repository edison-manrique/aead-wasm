const PORT = 3000

Bun.serve({
  port: PORT,
  async fetch(req) {
    const url = new URL(req.url)

    // Si acceden a la raíz, redirigimos a la ruta del ejemplo
    const pathname = url.pathname === "/" ? "/examples/index.html" : url.pathname

    // Construimos la ruta del archivo subiendo un nivel (..)
    const filePath = `${import.meta.dir}/..${pathname}`
    const file = Bun.file(filePath)

    // Si el archivo existe, Bun lo sirve determinando el Content-Type automáticamente
    if (await file.exists()) {
      return new Response(file)
    }

    return new Response(`404 Not Found: ${url.pathname}`, { status: 404 })
  }
})

console.log(`🚀 Servidor de ejemplo AEAD-WASM ejecutándose en http://localhost:${PORT}/examples/index.html`)
