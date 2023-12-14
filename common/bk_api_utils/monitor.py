"""统一监控中心接口"""
from apps.big_screen import constants as screen_constants
from common.bk_api_utils.main import ApiManager


class MonitorApiUtils(object):
    @staticmethod
    def search_topology_graph_by_level(biz_ids, level=6):
        """根据级别和业务ID列表查询业务拓扑"""
        company_topo = {
            "alarm_level": "0",
            "bk_inst_id": 0,
            "bk_inst_name": screen_constants.COMPANY_NAME,
            "bk_obj_id": "company",
            "bk_obj_name": "公司",
            "children": [],
        }
        for biz_id in biz_ids:
            biz_topo = ApiManager.monitor.search_topology_graph_by_level(bk_biz_id=biz_id, level=level).get("data", {})
            biz_topo = MonitorApiUtils._parse_biz_topo(biz_topo)
            company_topo["children"].append(biz_topo)
        return company_topo

    @staticmethod
    def _parse_biz_topo(biz_topo, enable_ignore=True, enable_filter=True):
        """
        解析业务拓扑
        :param biz_topo: 业务拓扑的数据
        :param enable_ignore: 启动忽略,参考/apps/big_screen/constants的IGNORE_LEVEL_BK_OBJ_IDS
        :param enable_filter: 启动过滤,参考/apps/big_screen/constants的FILTER_BK_INST_NAME
        :return: 业务拓扑的数据
        """

        biz_topo["children"] = MonitorApiUtils._parse_topo_list(
            biz_topo.get("children", []), enable_ignore, enable_filter
        )
        return biz_topo

    @staticmethod
    def _parse_topo_list(topo_list, enable_ignore, enable_filter):
        """
        递归解析拓扑children列表
        :param topo_list: 业务拓扑的数据
        :param enable_ignore: 启动忽略,参考/apps/big_screen/constants的IGNORE_LEVEL_BK_OBJ_IDS
        :param enable_filter: 启动过滤,参考/apps/big_screen/constants的FILTER_BK_INST_NAME
        :return: 业务拓扑的数据
        """
        if not topo_list:
            return topo_list
        # 去除空闲机组
        topo_list = [topo for topo in topo_list if topo.get("bk_inst_name", "") != screen_constants.LEISURE_POOL]
        # 此次的忽略状态
        has_ignore = False
        has_filter = False
        has_child_filter = False
        filter_names = []
        child_filter_names = []
        bk_obj_id = topo_list[0]["bk_obj_id"] if topo_list else None
        child0 = topo_list[0].get("children") if topo_list else None
        child_bk_obj_id = child0[0]["bk_obj_id"] if child0 else None
        # 是否需要忽略
        if enable_ignore:
            # 如果模型在忽略列表里
            if child_bk_obj_id in screen_constants.IGNORE_LEVEL_BK_OBJ_IDS:
                has_ignore = True
            # 如果在忽略列表里且还需要子级开始过滤
            if enable_filter and child_bk_obj_id in screen_constants.FILTER_BK_INST_NAME:
                has_child_filter = True
                child_filter_names.append(screen_constants.FILTER_BK_INST_NAME[child_bk_obj_id])
        if enable_filter and bk_obj_id in screen_constants.FILTER_BK_INST_NAME:
            has_filter = True
            filter_names.append(screen_constants.FILTER_BK_INST_NAME[bk_obj_id])

        for topo in topo_list:
            children = topo.get("children", [])
            if has_ignore:
                new_children = []
                [
                    new_children.extend(i.get("children", []))
                    for i in children
                    if not has_child_filter or (has_child_filter and i["bk_inst_id"] in child_filter_names)
                ]
                children = new_children
            elif not has_ignore and has_filter:
                children = [i for i in children if i["bk_inst_id"] in filter_names]
            topo["children"] = MonitorApiUtils._parse_topo_list(children, enable_ignore, enable_filter)
        return topo_list
