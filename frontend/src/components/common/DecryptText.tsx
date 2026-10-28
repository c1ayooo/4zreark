import { useEffect, useState } from 'react'

// 一次性解密入场：随机字符逐位落定为最终文本。只给登录页标题用——
// 单次播放不循环，与「侦察/测绘」的产品气质契合；禁止挪进业务页面。
const SCRAMBLE = '!<>-_\\/[]{}=+*^?#01'

export function DecryptText({
  text,
  className,
  duration = 900,
}: {
  text: string
  className?: string
  duration?: number
}) {
  const [out, setOut] = useState(text)

  useEffect(() => {
    // 减少动效偏好：跳过打乱过程直接显示终态
    if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return
    const start = performance.now()
    let raf = 0
    const tick = (now: number) => {
      const p = Math.min(1, (now - start) / duration)
      const settled = Math.floor(p * text.length)
      let s = text.slice(0, settled)
      for (let i = settled; i < text.length; i++) {
        s += SCRAMBLE[Math.floor(Math.random() * SCRAMBLE.length)]
      }
      setOut(s)
      if (p < 1) raf = requestAnimationFrame(tick)
      else setOut(text)
    }
    raf = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(raf)
  }, [text, duration])

  return (
    <span className={className} aria-label={text}>
      {out}
    </span>
  )
}
