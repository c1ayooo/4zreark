-- 监控计划完整性：一个种子最多一条计划，种子删除时计划必须一起消失。
--
-- 背景：monitoring_plans.seed_id 此前既没有外键也没有唯一约束，
--   1) 删除种子（项目删除、种子清理、ICP 回灌重跑）后计划变成孤儿，
--      调度器仍按 next_run_at 触发，白白消耗采集配额，日志里看不出异常；
--   2) 并发回灌可能给同一 seed 建出多条计划（PromoteICPFilings 只靠
--      NOT EXISTS 防重，不是原子约束）。
-- 本迁移先清孤儿与重复，再补唯一约束与外键。
--
-- 幂等：可重复执行。

-- 1) 清孤儿计划
delete from monitoring_plans p
 where not exists (select 1 from seeds s where s.id = p.seed_id);

-- 2) 同一 seed 的多余计划只保留最早一条
delete from monitoring_plans p
 using monitoring_plans q
 where p.seed_id = q.seed_id
   and p.id > q.id;

-- 3) 一个种子一条计划
create unique index if not exists monitoring_plans_seed_uniq
    on monitoring_plans (seed_id);

-- 4) 种子删除级联删计划
do $$
begin
    if not exists (
        select 1 from pg_constraint
         where conrelid = 'monitoring_plans'::regclass
           and conname  = 'monitoring_plans_seed_fk'
    ) then
        alter table monitoring_plans
            add constraint monitoring_plans_seed_fk
            foreign key (seed_id) references seeds(id) on delete cascade;
    end if;
end $$;
