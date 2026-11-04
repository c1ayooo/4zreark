package repo

import "context"

// RemoveTechLabels 从 sites.tech 中剔除指定词条，返回受影响行数。
//
// 存在的理由：tech 是「只增不减」的合并列（见 UpdateSiteProfile 的注释），
// 一旦误报写进去就永远留在画像里。sensitive.yaml 里的条目曾经被当成技术栈
// 写入（Linkfinder、系统绝对路径泄漏、内网IP 等），不做一次清理，统计与
// 筛选会一直被这些非技术词条污染。
//
// 只删传入的词条、只动数组元素：调用方要用「规则库里的敏感特征名」作为
// 唯一来源，不要把这里当成通用清洗入口。
func (r *Repo) RemoveTechLabels(ctx context.Context, labels []string) (int64, error) {
	if len(labels) == 0 {
		return 0, nil
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE sites
		   SET tech = coalesce((
		         SELECT jsonb_agg(e ORDER BY e)
		           FROM jsonb_array_elements_text(sites.tech) e
		          WHERE e <> ALL($1::text[])
		       ), '[]'::jsonb)
		 WHERE jsonb_typeof(tech) = 'array'
		   AND tech ?| $1::text[]`, labels)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
