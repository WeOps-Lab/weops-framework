import re

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig

from apps.syslog.utils.api import graylog_api
from blueapps.core.exceptions import ServerBlueException
from utils.thread_pool import ThreadPool


class LogClustering(object):
    def __init__(self, search_id, query_id, search_type_id, time_range, total_count):
        self.search_id = search_id
        self.query_id = query_id
        self.search_type_id = search_type_id
        self.time_range = time_range
        self.total_count = total_count

    def get_logs(self, limit, offset):
        """
        获取日志
        :return:
        """
        try:
            search_data = {
                "global_override": {
                    "timerange": self.time_range,
                    "keep_search_types": [self.search_type_id],
                    "search_types": {self.search_type_id: {"limit": limit, "offset": offset}},
                }
            }
            resp = graylog_api.search_input_logs(url_param_dict=dict(id=self.search_id), json=search_data)
            return dict(
                task_id=offset,
                data=resp["data"]["results"][self.query_id]["search_types"][self.search_type_id]["messages"],
            )
        except Exception as e:
            raise ServerBlueException(f"查询失败，详情：{e}")

    def async_get_logs(self, _limit=2000):
        limit_list = []
        if self.total_count <= _limit:
            limit_list.append(self.total_count)
        else:
            request_count = self.total_count // _limit
            for i in range(request_count):
                limit_list.append(_limit)
            limit_list.append(self.total_count % _limit)

        pool = ThreadPool()
        for index, limit in enumerate(limit_list):
            pool.add_task(self.get_logs, limit, index * _limit)
        pool.wait_end()
        return pool.get_result(format_type="dict")

    def go_clustering_by_drains(self, sim_th=None):
        """
        使用drains进行日志聚类
        """
        results_dict = self.async_get_logs()
        config = TemplateMinerConfig()
        config.load("./apps/syslog/drain3.ini")
        config.profiling_enabled = False
        if sim_th:
            config.drain_sim_th = sim_th
        template_miner = TemplateMiner(config=config)
        log_clustering_dict = {}
        for key in sorted(results_dict.keys()):
            for log in results_dict[key]:
                result = template_miner.add_log_message(log["message"]["message"])  # 添加日志到模式挖掘器中
                log_clustering_dict[result["cluster_id"]] = {
                    "cluster_id": result["cluster_id"],
                    "template": result["template_mined"],
                    "size": result["cluster_size"],
                }
        for val in log_clustering_dict.values():
            # val["template"] = self.format_template(val["template"])
            val["percentage"] = round(val["size"] / self.total_count * 100, 2)
        return dict(count=len(log_clustering_dict), data=list(log_clustering_dict.values()))

    def format_template(self, template):
        """
        格式化模板
        """
        # 定义需要转义的特殊字符列表
        special_characters = r'&|:\/+-!(){}[]^"~*?'
        # 将特殊字符转义
        template = re.sub(f"[{re.escape(special_characters)}]", r"\\\g<0>", template)
        # 将模板中的<\:\*\:>替换为*
        template = template.replace(r"<\:\*\:>", "*")
        return template
