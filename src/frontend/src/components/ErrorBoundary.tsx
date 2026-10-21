import React from 'react'
import { Button } from '@/components/ui/button'

interface Props {
  children: React.ReactNode
}

interface State {
  error: Error | null
}

/**
 * 路由级兜底：页面组件抛错时保留应用外壳，显示错误而不是整页白屏。
 * 具体错误同时打到浏览器 console，方便继续排查。
 */
export class ErrorBoundary extends React.Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error('[UI] render error', error, info)
  }

  render() {
    if (this.state.error) {
      return (
        <div className="p-6">
          <div className="mx-auto max-w-2xl rounded-lg border bg-card p-6 space-y-4">
            <h2 className="text-xl font-semibold">页面渲染出错</h2>
            <p className="text-sm text-muted-foreground">
              错误信息已输出到浏览器 Console。可以先刷新页面；如果持续出现，请把下面的信息发给我。
            </p>
            <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded-md bg-muted p-3 text-xs">
              {this.state.error.message}
              {'\n'}
              {this.state.error.stack}
            </pre>
            <Button onClick={() => window.location.reload()}>刷新页面</Button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
