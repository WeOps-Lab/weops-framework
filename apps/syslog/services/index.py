from apps.syslog.utils.api import graylog_api
from blueapps.core.exceptions import ServerBlueException


class IndexSetService(object):
    @staticmethod
    def default_index(id):
        """索引集"""
        resp = graylog_api.default_index(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def delete_index(id, kwargs):
        """索引集"""
        resp = graylog_api.delete_index(url_param_dict=dict(id=id), params=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def add_index(kwargs):
        """索引集"""
        resp = graylog_api.add_index(json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def update_index(id, kwargs):
        """索引集"""
        resp = graylog_api.update_index(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def index_set(id):
        """索引集详情"""
        resp = graylog_api.index_set(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def index_rebuild(index_name):
        """重新计算索引范围"""
        resp = graylog_api.index_rebuild(url_param_dict=dict(index_name=index_name))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def index_reopen(index_name):
        """重新打开索引"""
        resp = graylog_api.index_reopen(url_param_dict=dict(index_name=index_name))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def index_close(index_name):
        """关闭索引"""
        resp = graylog_api.index_close(url_param_dict=dict(index_name=index_name))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def index_delete(index_name):
        """删除索引"""
        resp = graylog_api.index_delete(url_param_dict=dict(index_name=index_name))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def index_set_rebuild(id):
        """更新索引集范围"""
        resp = graylog_api.index_set_rebuild(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")

    @staticmethod
    def create_index(id, kwargs):
        """创建新索引"""
        resp = graylog_api.create_index(url_param_dict=dict(id=id), json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def index_set_overview(id):
        """索引集索引数据详情"""
        resp = graylog_api.index_set_overview(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def indexs(id):
        """索引列表"""
        resp = graylog_api.indexs(url_param_dict=dict(id=id))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def indexs_multiple(data):
        """查询展开索引的信息"""
        resp = graylog_api.indexs_multiple(json=data)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]

    @staticmethod
    def index_sets_stats(kwargs):
        """获取全局索引集"""
        resp = graylog_api.index_sets_stats(params=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"执行失败，详情：{msg}")
        return resp["data"]
