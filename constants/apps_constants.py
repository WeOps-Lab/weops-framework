# -- coding: utf-8 --

USER_CACHE_KEY = "USER_BK_USERNAME_CHNAME"

BK_USERNAME_CHNAME_CHANGE = {
    "host": ["operator", "bk_bak_operator"],
    "biz": ["operator", "bk_biz_tester", "bk_biz_developer", "bk_biz_productor", "bk_biz_maintainer"],
}

# 模型分类存储在配置数据库的key
CLASSIFICATIONS_GROUP = "classifications_group"

# 监控的模型分类存储在配置数据库的key
MONITOR_GROUP = "monitor_group"

# 模型设置模块不参与展示的模型分类
FILTER_CLASSIFICATIONS = ["bk_biz_topo", "bk_organization", "bk_uncategorized"]
