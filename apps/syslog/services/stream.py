from apps.syslog.constants import PAGE_INFO
from apps.syslog.models import RoleStream, Stream
from apps.syslog.utils.api import graylog_api
from apps.system_mgmt.models import SysRole
from blueapps.core.exceptions import ServerBlueException


class StreamService(object):
    @staticmethod
    def streams(user, kwargs):
        """查询数据流"""
        page, page_size = int(kwargs.get("page", 1)), int(kwargs.get("page_size", 10))
        start, end = (page - 1) * page_size, page * page_size
        query = kwargs.get("search")
        query_set = Stream.objects.all()
        if query:
            query_set = query_set.filter(title__contains=query)

        count = query_set.count()

        if page_size == -1:
            query_set = query_set.order_by("-updated_at")
        else:
            query_set = query_set.order_by("-updated_at")[start:end]

        stream_map = {i.id: i for i in query_set}

        resp = graylog_api.get_streams(params=PAGE_INFO)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        streams = resp["data"]["streams"]

        items = []

        for stream in streams:
            if stream["id"] not in stream_map:
                continue
            stream.update(updated_at=stream_map[stream["id"]].updated_at)
            items.append(stream)
        items.sort(key=lambda x: x["updated_at"], reverse=True)
        return dict(count=count, items=items)

    @staticmethod
    def add_stream(user, kwargs):
        """创建数据流"""
        resp = graylog_api.add_stream(json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        Stream.objects.create(id=resp["data"]["stream_id"], title=kwargs["title"], created_by=user)
        return resp["data"]["stream_id"]

    @staticmethod
    def start_stream(id):
        resp = graylog_api.start_stream(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def update_stream(user, id, kwargs):
        """更新数据流"""
        resp = graylog_api.update_stream(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        Stream.objects.filter(id=id).update(title=kwargs["title"], updated_by=user)

    @staticmethod
    def delete_stream(user, id):
        """删除数据流"""
        resp = graylog_api.delete_stream(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        obj = Stream.objects.filter(id=id).first()
        title = obj.title
        obj.delete()
        return title

    @staticmethod
    def stream_detail(user, id):
        """数据流详情"""
        resp = graylog_api.stream_detail(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def clone_stearm(user, id, kwargs):
        """克隆消息流"""
        resp = graylog_api.clone_stream(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        Stream.objects.create(id=resp["data"]["stream_id"], title=kwargs["title"], created_by=user)
        return resp["data"]["stream_id"]

    @staticmethod
    def rule_types(id):
        """查询规则类型"""
        resp = graylog_api.rule_types(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def relative(kwargs):
        """查询规则"""
        resp = graylog_api.relative(params=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def test_match(id, kwargs):
        """验证规则"""
        resp = graylog_api.test_match(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def add_rule(id, kwargs):
        """新增验证规则"""
        resp = graylog_api.add_rule(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def rule_detail(id, rule_id):
        """规则详情"""
        resp = graylog_api.rule_detail(url_param_dict=dict(id=id, rule_id=rule_id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def update_rule(id, rule_id, kwargs):
        """修改规则"""
        resp = graylog_api.update_rule(url_param_dict=dict(id=id, rule_id=rule_id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def del_rule(id, rule_id):
        """删除验证规则"""
        resp = graylog_api.del_rule(url_param_dict=dict(id=id, rule_id=rule_id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def system_fields():
        """删除验证规则"""
        resp = graylog_api.system_fields()
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def index_sets(kwargs):
        """索引集"""
        resp = graylog_api.index_sets(params=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def system_inputs():
        """匹配输入值列表"""
        resp = graylog_api.system_inputs()
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def get_role_streams(role_id):
        """查询角色数据流列表"""
        obj = RoleStream.objects.filter(role_id=role_id).first()
        return obj.stream_list if obj else []

    @staticmethod
    def set_role_streams(role_id, stream_list):
        """设置角色数据流"""
        RoleStream.objects.update_or_create(role_id=role_id, defaults=dict(stream_list=stream_list))

    @staticmethod
    def get_user_streams(username, is_super):
        """查询用户授权的数据流"""
        if is_super:
            return [{"id": i.id, "title": i.title} for i in Stream.objects.all()]
        role_objs = SysRole.objects.filter(sysuser__bk_username=username)
        role_stream_objs = RoleStream.objects.filter(role_id__in=[i.id for i in role_objs])
        stream_set = set()
        for role_stream_obj in role_stream_objs:
            for stream_id in role_stream_obj.stream_list:
                stream_set.add(stream_id)
        streams = Stream.objects.filter(id__in=stream_set)
        return [{"id": i.id, "title": i.title} for i in streams]
