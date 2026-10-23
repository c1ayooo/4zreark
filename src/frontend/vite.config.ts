import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import path from 'path'

export default defineConfig(({ command }) => ({
  // 构建产物挂 /static：/assets 是前端自己的资产页路由，
  // 与 dist/assets 同名会互相劫持（直接访问/刷新资产页会白屏）。
  // 开发态仍用 /，否则 vite dev 的所有路由都会带上 /static 前缀。
  base: command === 'build' ? '/static/' : '/',
  plugins: [react()],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
  server: {
    port: 5173,
    proxy: {
      '/api': {
        target: 'http://localhost:8080',
        changeOrigin: true,
        ws: true, // Enable WebSocket proxy
      },
    },
  },
  build: {
    // 路由级 lazy 已把页面拆开；这里再把稳定的第三方依赖按用途分组，
    // 避免单个 1.6MB 的入口包，也让浏览器缓存跨页面复用。
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (!id.includes('node_modules')) return
          if (id.includes('@xyflow')) return 'vendor-flow'
          if (id.includes('recharts') || id.includes('d3-') || id.includes('victory')) return 'vendor-charts'
          // antd 全家（antd / rc-* / @ant-design / dayjs）独立分块，只被用到它的页面加载
          if (
            id.includes('/antd/') ||
            id.includes('/rc-') ||
            id.includes('@rc-component') ||
            id.includes('@ant-design') ||
            id.includes('/dayjs/') ||
            id.includes('async-validator') ||
            id.includes('rc-util')
          )
            return 'vendor-antd'
          if (id.includes('framer-motion') || id.includes('motion-dom') || id.includes('motion-utils'))
            return 'vendor-motion'
          if (id.includes('@tanstack')) return 'vendor-query'
          // React / react-dom / react-router 留在 vendor：单独拆 vendor-react 会与
          // vendor 互相 import，形成 chunk 环，运行时抛 forwardRef undefined。
          return 'vendor'
        },
      },
    },
  },
}))
