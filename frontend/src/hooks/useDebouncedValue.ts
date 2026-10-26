import { useEffect, useState } from 'react'

// 值防抖：输入框逐键 setState 时，让跟随 value 的 useQuery 请求按延迟收敛。
// 典型用法：const q = useDebouncedValue(rawQ) 然后把 q 放进 queryKey。
export function useDebouncedValue<T>(value: T, delay = 300): T {
  const [debounced, setDebounced] = useState(value)
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay)
    return () => clearTimeout(t)
  }, [value, delay])
  return debounced
}
