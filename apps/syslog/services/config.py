# -- coding: utf-8 --

# @File : config.py
# @Time : 2023/6/9 14:47
# @Author : windyzhao

from apps.syslog.utils.api import graylog_api


class SidecarConfigurationService(object):
    @classmethod
    def search_collectors_id(cls, collectors_name: str, os_type: str):
        """
        通过采集器名称和操作系统类型查询采集器id
        """
        params = {"page": 1, "per_page": 10, "query": collectors_name}
        resp = graylog_api.get_collectors_summary(params=params)
        if not resp["result"]:
            return
        for _value in resp["data"]["collectors"]:
            if _value["node_operating_system"] == os_type.lower():
                return _value["id"]

    @classmethod
    def get_collectors(cls, os_value, params):
        """
        需要先查询所有的采集器，拿到采集器id
        """
        result = {}
        resp = graylog_api.get_collectors_summary(params=params)
        if not resp["result"]:
            return result

        for collector in resp["data"]["collectors"]:
            if os_value:
                if collector["node_operating_system"] == os_value:
                    result[collector["id"]] = collector
            else:
                result[collector["id"]] = collector

        return result

    @classmethod
    def get_configurations(cls, params):
        """
        查询配置
        默认 id desc
        统一查询配置(带过滤)，再进行采集器/采集器操作系统
        的过滤，最后手动分页+统计总数
        params: 参数
        query_type：
            os_type: 系统类型
            name: 配置名称
            collector_name: 探针类型
            configurations_id: 配置id
        query:
        {
        "os_type":linux,
        "config_name:"配置名称"
        }
        """

        page = params["page"]
        page_size = params["page_size"]
        query_dict = params["query"]

        os_value = query_dict.get("os_type", "")
        config_value = query_dict.get("name", "")
        collectors_value = query_dict.get("collector_name", "")
        search_configurations_id = query_dict.get("configurations_id", "")

        result = {"count": 0, "page": page, "page_size": page_size, "data": []}

        # 查询采集器
        collectors_params = {"page": 1, "per_page": 99999, "query": collectors_value, "sort": "_id", "order": "desc"}
        collectors_map = cls.get_collectors(os_value, collectors_params)
        if not collectors_map:
            return result

        # 查询配置数据
        config_params = {
            "page": 1,
            "per_page": 99999,
            "query": config_value,
            "sort": "_id",
            "order": "desc",
        }
        configurations_dict = graylog_api.get_collectors_configurations(params=config_params)
        if not configurations_dict["result"]:
            return result

        # 查询sidecar概览
        sidecar_data = graylog_api.get_sidecars(json={"query": "", "page": 1, "per_page": 99999})
        if not sidecar_data["result"]:
            return result
        sidecar_map = cls.format_nodes_map(sidecar_data["data"].get("sidecars", []))

        for configuration in configurations_dict["data"]["configurations"]:
            # 进行探针过滤
            collectors_dict = collectors_map.get(configuration["collector_id"])
            if collectors_dict is None:
                continue

            # 进行操作系统过滤
            os_type = collectors_dict["node_operating_system"]
            if os_value and os_value != os_type:
                continue

            configuration.pop("color", "")
            node_data = sidecar_map.get(configuration["id"], [])
            configuration["os_type"] = os_type
            configuration["collector_id"] = collectors_dict["id"]
            configuration["collector_name"] = collectors_dict["name"]
            configuration["use_nodes"] = {"count": len(node_data), "nodes": node_data}  # 已用节点数  # 节点node_name

            if not search_configurations_id:
                result["data"].append(configuration)
                continue

            # 做查询单id的配置
            if configuration["id"] == search_configurations_id:
                result["data"].append(configuration)
                break

        result["count"] = len(result["data"])
        result["data"] = result["data"][(page - 1) * page_size : page * page_size]

        return result

    @classmethod
    def _format_nodes_map(cls, sidecars):
        """
        格式化节点数据
        找到在节点上安装了采集器且启动起来的采集器
        """
        result = {}

        for sidecar in sidecars:
            node_details = sidecar["node_details"]
            status = node_details["status"]
            if not status:
                continue

            os_type = node_details["operating_system"].lower()
            for collector in status["collectors"]:
                collector_id = collector["collector_id"]
                result.setdefault(f"{collector_id}-{os_type}", []).append(
                    {"node_id": sidecar["node_id"], "node_name": sidecar["node_name"]}
                )

        return result

    @classmethod
    def format_nodes_map(cls, sidecars):
        result = {}
        for sidecar in sidecars:
            node_id = sidecar["node_id"]
            node_name = sidecar["node_name"]
            assignments = sidecar["assignments"]
            for assignment in assignments:
                result.setdefault(assignment["configuration_id"], []).append(
                    {
                        "node_id": node_id,
                        "node_name": node_name,
                    }
                )
        return result

    @classmethod
    def get_node_data(cls):
        sidecar_data = graylog_api.get_sidecars(json={"query": "", "page": 1, "per_page": 99999})
        if not sidecar_data["result"]:
            return
        result = {}
        sidecars = sidecar_data["data"]["sidecars"]
        for sidecar in sidecars:
            result[sidecar["node_name"]] = {"node_id": sidecar["node_id"], "assignments": sidecar["assignments"]}

        return result

    @classmethod
    def get_nodes(cls, collector_id, os_type):
        """
        查询节点下 使用/未使用 此采集器的节点
        collector_id: 采集器ID
        use: 使用/未使用
        但是前提是 此节点数必须是启用了这个采集器
        """

        result = []
        use_result = []
        resp = graylog_api.get_sidecars(json={"query": "", "page": 1, "per_page": 99999})
        if not resp["result"]:
            return use_result, result

        sidecars = resp["data"]["sidecars"]
        for sidecar in sidecars:
            node_name = sidecar["node_name"]
            node_details = sidecar["node_details"]
            if os_type != node_details["operating_system"].lower():
                continue

            status = node_details["status"]
            if not status:
                result.append(node_name)
                continue

            collector_bool = []
            for collector in status["collectors"]:
                collector_bool.append(collector_id == collector["collector_id"])

            if any(collector_bool):
                use_result.append(node_name)
            else:
                result.append(node_name)

        return use_result, result
