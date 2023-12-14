import json

from apps.syslog.constants import GRAYLOG_AUTH, GRAYLOG_URL, NOTICE_NAME
from apps.syslog.models import AlarmStrategy
from apps.syslog.utils.api import graylog_api
from apps.syslog.utils.import_local_log import LogService
from apps.syslog.utils.log_clustering import LogClustering
from blueapps.core.exceptions import ServerBlueException
from common.casbin_inst_service import CasBinInstService
from common.execute_big_file import BigFile
from utils.app_log import logger
from utils.thread_pool import ThreadPool


def time_to_str(time_obj):
    return str(time_obj).replace("T", " ")[:19]


class SyslogService(object):
    @staticmethod
    def views_functions(**kwargs):
        resp = graylog_api.views_functions(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def view_detail(**kwargs):
        resp = graylog_api.view_detail(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def entity_types(**kwargs):
        resp = graylog_api.entity_types(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_logs(**kwargs):
        resp = graylog_api.search_logs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def suggest(**kwargs):
        resp = graylog_api.suggest(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_input_logs(**kwargs):
        resp = graylog_api.search_input_logs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def views_fields(**kwargs):
        resp = graylog_api.views_fields(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_views_fields(**kwargs):
        resp = graylog_api.search_views_fields(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_saved(**kwargs):
        resp = graylog_api.search_saved(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def add_views(**kwargs):
        resp = graylog_api.add_views(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def update_views(**kwargs):
        resp = graylog_api.update_views(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def delete_views(**kwargs):
        resp = graylog_api.delete_views(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def export_views_by_id_and_type(**kwargs):
        resp = graylog_api.export_views_by_id_and_type(**kwargs)
        content = resp["data"].content.decode()
        if resp["data"].status_code >= 300:
            result = json.loads(content)
            msg = f"错误类型{result.get('type')}，详情{result.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"].content

    @staticmethod
    def download_files(job_id, filename):
        download_url = f"{GRAYLOG_URL}/api/views/search/messages/job/{job_id}/{filename}"
        headers = {"Authorization": f"Basic {GRAYLOG_AUTH}"}
        return BigFile(download_url, filename, headers).download()

    @staticmethod
    def search_nodes(**kwargs):
        resp = graylog_api.search_nodes(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_inputs_types(**kwargs):
        resp = graylog_api.search_inputs_types(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_inputs(**kwargs):
        resp = graylog_api.search_inputs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_input(**kwargs):
        resp = graylog_api.search_input(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def create_inputs(**kwargs):
        resp = graylog_api.create_inputs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def update_input(**kwargs):
        resp = graylog_api.update_input(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def delete_input(**kwargs):
        resp = graylog_api.delete_input(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def inputstates(**kwargs):
        resp = graylog_api.inputstates(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def add_staticfields(**kwargs):
        resp = graylog_api.add_staticfields(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def del_staticfields(**kwargs):
        resp = graylog_api.del_staticfields(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def metrics(**kwargs):
        resp = graylog_api.metrics(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def contains_string_tester(**kwargs):
        resp = graylog_api.contains_string_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def regex_tester(**kwargs):
        resp = graylog_api.regex_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def grok_tester(**kwargs):
        resp = graylog_api.grok_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def json_tester(**kwargs):
        resp = graylog_api.json_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def regex_replace_tester(**kwargs):
        resp = graylog_api.regex_replace_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def split_and_index_tester(**kwargs):
        resp = graylog_api.split_and_index_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def substring_tester(**kwargs):
        resp = graylog_api.substring_tester(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def get_locales(**kwargs):
        resp = graylog_api.get_locales(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def get_grok(**kwargs):
        resp = graylog_api.get_grok(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def open_inputs(**kwargs):
        resp = graylog_api.open_inputs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def close_inputs(**kwargs):
        resp = graylog_api.close_inputs(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    # 告警策略
    @staticmethod
    def get_notifications():
        resp = graylog_api.get_notifications(params=dict(query=NOTICE_NAME))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]["notifications"]

    @staticmethod
    def update_field_to_field_spec(data):
        """默认添加字段gl2_message_id到事件附加字段"""
        data["field_spec"]["gl2_message_id"] = {
            "data_type": "string",
            "providers": [
                {
                    "template": "${source." + "gl2_message_id" + "}",
                    "type": "template-v1",
                }
            ],
        }

    @staticmethod
    def create_event_definitions(username, **kwargs):
        """创建告警事件与告警通知"""

        SyslogService.update_field_to_field_spec(kwargs)

        notifications = SyslogService.get_notifications()
        if notifications:
            kwargs.update(notifications=[{"notification_id": notifications[0]["id"], "notification_parameters": None}])

        resp = graylog_api.create_event_definitions(json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        result = resp["data"]

        obj = AlarmStrategy.objects.create(
            event_definition_id=result["id"],
            title=result["title"],
            created_by=username,
            updated_by=username,
        )
        result.update(**{"created_at": time_to_str(obj.created_at), "updated_at": time_to_str(obj.updated_at)})
        return result

    @staticmethod
    def get_event_definitions(**kwargs):

        query_set = AlarmStrategy.objects.all()

        if not kwargs["is_super"]:
            definitions = CasBinInstService.get_user_instances(
                username=kwargs["username"], instance_type="监控策略", bk_obj_id="log"
            )
            empower_inst_set = set(
                AlarmStrategy.objects.filter(created_by=kwargs["username"]).values_list(
                    "event_definition_id", flat=True
                )
            )

            empower_inst_set.update(set(definitions))

            if empower_inst_set:
                query_set = query_set.filter(event_definition_id__in=empower_inst_set)

        query = kwargs.get("query", {})

        if query.get("query"):
            query_set = query_set.filter(title__contains=query["query"])

        page, page_size = int(query.get("page", 1)), int(query.get("per_page", 10))
        start, end = (page - 1) * page_size, page * page_size

        count = query_set.count()

        query_set = query_set.order_by("-updated_at")[start:end]

        items = [
            dict(
                event_definition_id=obj.event_definition_id,
                title=obj.title,
                is_scheduled=obj.is_scheduled,
                created_at=obj.created_at,
                updated_at=obj.updated_at,
            )
            for obj in query_set
        ]

        return dict(count=count, items=items)

    @staticmethod
    def event_definitions_validate(**kwargs):
        resp = graylog_api.event_definitions_validate(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_notifications(**kwargs):
        resp = graylog_api.search_notifications(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def search_event_definitions(definitionId: str):
        resp = graylog_api.search_event_definitions(url_param_dict=dict(definitionId=definitionId))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        result = resp["data"]
        obj = AlarmStrategy.objects.filter(event_definition_id=definitionId).first()
        if obj:
            result.update(**{"created_at": time_to_str(obj.created_at), "updated_at": time_to_str(obj.updated_at)})
        return result

    @staticmethod
    def update_notifications(**kwargs):
        resp = graylog_api.update_notifications(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def update_event_definitions(definitionId, username, **kwargs):

        del kwargs["created_at"]
        del kwargs["updated_at"]

        SyslogService.update_field_to_field_spec(kwargs)

        resp = graylog_api.update_event_definitions(
            url_param_dict=dict(definitionId=definitionId),
            json=kwargs,
        )
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        result = resp["data"]

        obj = AlarmStrategy.objects.filter(event_definition_id=definitionId).first()
        if obj:
            obj.updated_by = username
            obj.title = kwargs["title"]
            obj.save()
            result.update(**{"created_at": time_to_str(obj.created_at), "updated_at": time_to_str(obj.updated_at)})
        return result

    @staticmethod
    def delete_notifications(**kwargs):
        resp = graylog_api.delete_notifications(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def delete_event_definitions(definitionId: str):
        resp = graylog_api.delete_event_definitions(url_param_dict=dict(definitionId=definitionId))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        instances = AlarmStrategy.objects.filter(event_definition_id=definitionId)
        created_by = instances.first().created_by if instances.first() is not None else ""
        instances.delete()
        return created_by

    @staticmethod
    def schedule_event_definitions(**kwargs):
        resp = graylog_api.schedule_event_definitions(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        AlarmStrategy.objects.filter(event_definition_id=kwargs["url_param_dict"]["definitionId"]).update(
            is_scheduled=True
        )
        return resp["data"]

    @staticmethod
    def unschedule_event_definitions(**kwargs):
        resp = graylog_api.unschedule_event_definitions(**kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        AlarmStrategy.objects.filter(event_definition_id=kwargs["url_param_dict"]["definitionId"]).update(
            is_scheduled=False
        )
        return resp["data"]

    @staticmethod
    def batch_schedule_event_definitions(definitionids: list):
        schedule_event_definitions_drf = lambda x: dict(  # noqa
            task_id=x, data=SyslogService.schedule_event_definitions(url_param_dict=dict(definitionId=x))
        )
        pool = ThreadPool()
        for definitionid in definitionids:
            pool.add_task(schedule_event_definitions_drf, definitionid)
        pool.wait_end()

    @staticmethod
    def batch_unschedule_event_definitions(definitionids: list):
        unschedule_event_definitions_drf = lambda x: dict(  # noqa
            task_id=x, data=SyslogService.unschedule_event_definitions(url_param_dict=dict(definitionId=x))
        )
        pool = ThreadPool()
        for definitionid in definitionids:
            pool.add_task(unschedule_event_definitions_drf, definitionid)
        pool.wait_end()

    @staticmethod
    def get_extractors(id):
        resp = graylog_api.get_extractors(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        resp["data"]["extractors"].sort(key=lambda x: x["order"])
        return resp["data"]

    @staticmethod
    def add_extractors(id, kwargs):
        resp = graylog_api.add_extractors(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def order_extractors(id, kwargs):
        resp = graylog_api.order_extractors(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def del_extractors(id, ex_id):
        resp = graylog_api.del_extractors(url_param_dict=dict(id=id, ex_id=ex_id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def update_extractors(id, ex_id, kwargs):
        resp = graylog_api.update_extractors(url_param_dict=dict(id=id, ex_id=ex_id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def extractor_detail(id, ex_id):
        resp = graylog_api.extractor_detail(url_param_dict=dict(id=id, ex_id=ex_id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def import_log(kwargs):
        """导入本地日志，通过推到kafka，再由graylog采集"""
        obj = LogService(kwargs.get("file").file, kwargs.get("file").content_type, kwargs.get("flak"))
        obj.push_log_to_kafka()

    @staticmethod
    def view_condition(id):
        """查询视图条件"""
        resp = graylog_api.view_condition(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def log_clustering(**kwargs):
        """日志聚类"""
        instance = LogClustering(
            kwargs["search_id"],
            kwargs["query_id"],
            kwargs["search_type_id"],
            kwargs["time_range"],
            kwargs["total_count"],
        )
        try:
            return instance.go_clustering_by_drains(kwargs.get("sim_th"))
        except Exception as e:
            logger.error(e)
            raise ServerBlueException("查询失败，日志数量超限!")
