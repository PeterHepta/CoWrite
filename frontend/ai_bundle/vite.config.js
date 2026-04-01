import { defineConfig } from 'vite'
export default defineConfig({
  build: {
    lib: {
      entry: 'entry.js',
      name: 'transformers',
      fileName: 'transformers.browser',
      formats: ['es']
    },
    outDir: '../',
    emptyOutDir: false,
    rollupOptions: {
      external: [],
    },
    target: 'es2020',
    minify: true,
  },
  resolve: {
    conditions: ['browser', 'import', 'default'],
    browserField: true,
  },
  define: {
    'process.env.NODE_ENV': '"production"',
  },
})
