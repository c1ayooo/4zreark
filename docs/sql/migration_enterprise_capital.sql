-- 企业实体补注册资本（qcc 详情页 RegistCapi），用于按资金规模筛目标
-- 场景：CNVD 事件型证书要求目标单位注册资金达到门槛（如 ≥ 5000 万）
-- 幂等：可重复执行

alter table zre.enterprise_entities
    add column if not exists registered_capital text not null default '';

alter table zre.enterprise_entities
    add column if not exists registered_capital_wan numeric(18, 2);

comment on column zre.enterprise_entities.registered_capital is '注册资本原文，如 6500万元';
comment on column zre.enterprise_entities.registered_capital_wan is '注册资本归一后的万元数值，外币按原值不换汇';

create index if not exists idx_enterprise_capital
    on zre.enterprise_entities (project_id, registered_capital_wan desc);
