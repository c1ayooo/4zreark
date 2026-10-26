import { assetApi } from '@/api/assets'

// 聚类视图(图标/技术栈)的纯展示:数据由父级查询,点击经 drillDown 变成
// 资产列表的过滤条件回到站点粒度。
export default function ClusterView({
  view,
  iconItems,
  iconTotal,
  iconLoading,
  techItems,
  techTotal,
  techLoading,
  drillDown,
}: {
  view: 'icons' | 'technologies'
  iconItems: { icon_sha256: string; sample_host?: string; sample_title?: string; site_count: number }[]
  iconTotal: number
  iconLoading: boolean
  techItems: { name: string; site_count: number }[]
  techTotal: number
  techLoading: boolean
  drillDown: (q: string) => void
}) {
  if (view === 'icons') {
    return (
      <div className="space-y-3">
        <p className="text-[13px] text-muted-foreground">
          共 {iconTotal} 组图标 · 点击图标下钻看对应站点(按内容哈希去重)
        </p>
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
          {iconItems.map((ic) => (
            <div
              key={ic.icon_sha256}
              role="button"
              tabIndex={0}
              title={`下钻:icon_hash="${ic.icon_sha256.slice(0, 12)}…"`}
              onClick={() => drillDown(`icon_hash="${ic.icon_sha256}"`)}
              onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') drillDown(`icon_hash="${ic.icon_sha256}"`) }}
              className="flex cursor-pointer flex-col items-center gap-2 rounded-md border p-3 transition-colors hover:border-foreground/30 hover:bg-muted/50"
            >
              <img
                src={assetApi.iconURL(ic.icon_sha256)}
                alt={ic.sample_host}
                className="h-10 w-10 rounded"
                onError={(e) => { (e.currentTarget as HTMLImageElement).style.visibility = 'hidden' }}
              />
              <div className="w-full truncate text-center text-[13px]" title={ic.sample_title || ic.sample_host}>
                {ic.sample_title || ic.sample_host}
              </div>
              <div className="text-[13px] text-muted-foreground">{ic.site_count} 个站点</div>
            </div>
          ))}
          {!iconLoading && iconItems.length === 0 && (
            <div className="col-span-full rounded border border-dashed py-8 text-center text-sm text-muted-foreground">
              还没有采集到图标(探测站点时会顺手抓 favicon)
            </div>
          )}
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <p className="text-[13px] text-muted-foreground">
        共 {techTotal} 种技术 · 点击技术名下钻看对应站点
      </p>
      <div className="flex flex-wrap gap-2">
        {techItems.map((t) => (
          <span
            key={t.name}
            role="button"
            tabIndex={0}
            onClick={() => drillDown(`app="${t.name.replace(/"/g, '')}"`)}
            onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') drillDown(`app="${t.name.replace(/"/g, '')}"`) }}
            className="cursor-pointer rounded-full border px-3 py-1 text-sm transition-colors hover:border-foreground/30 hover:bg-muted/50"
            title={`下钻:app="${t.name}"(${t.site_count} 个站点)`}
          >
            {t.name}
            <span className="ml-1 text-[13px] text-muted-foreground">{t.site_count}</span>
          </span>
        ))}
        {!techLoading && techItems.length === 0 && (
          <div className="w-full rounded border border-dashed py-8 text-center text-sm text-muted-foreground">
            还没有技术栈数据(需要先有指纹规则并探测过站点)
          </div>
        )}
      </div>
    </div>
  )
}
