# -- coding: utf-8 --

# @File : casbin_mesh_common.py
# @Time : 2023/4/19 10:03
# @Author : windyzhao
"""
casbin_mesh 的接口逻辑
"""
import typing

from common.casbin_mesh_api import casin_server
from utils.decorators import time_consuming


class CasbinMeshApiServer(object):

    @classmethod
    def create_namespace(cls, namespace: str):
        """
        创建命名空间
        namespace: 命名空间
        res:
            成功无返回
            失败返回类似:
            {
                "error": "namespace already existed"
            }
        """
        res = casin_server.create_namespace(ns=namespace)
        return res

    @classmethod
    def list_namespaces(cls):
        """
        查询namespace
        res:
            只返回设置了model的namespace
            ["weops_rbac"]
        """
        res = casin_server.list_namespaces()
        return res

    @classmethod
    @time_consuming
    def enforce(cls, namespace: str, params: typing.List[str]):
        """
        namespace: 命名空间
        params: 校验policy
        res:
            根据返回的ok的值来确定 True or False
        """
        res = casin_server.enforce(ns=namespace, params=params)
        if not res["success"]:
            return False
        if isinstance(res["data"], dict):
            return res["data"].get("ok", False)
        return False

    @classmethod
    def set_model(cls, namespace: str, text: str):
        """
        设置模型:
        namespace: 命名空间
        text: 模型配置
        """
        res = casin_server.set_model(ns=namespace, text=text)
        return res

    @classmethod
    def list_model(cls, namespace: str):
        """
        查询models
        """
        res = casin_server.list_model(ns=namespace)
        return res

    @classmethod
    def list_policies(cls, namespace: str, cursor: str = "", skip: int = 0, limit: int = 0, reverse: bool = False):
        """
        查询policy
        namespace: 命名空间
        cursor: 游标
        skip: 跳过多少条policy
        limit: 查询数量
        reverse: 倒序
        """
        kwargs = {'ns': namespace, 'reverse': reverse}
        if cursor:
            kwargs["cursor"] = cursor
        if skip:
            kwargs["skip"] = skip
        if limit:
            kwargs["skip"] = limit

        res = casin_server.list_policies(**kwargs)
        return res

    @classmethod
    def add_policies(cls, namespace: str, sec: str, ptype: str, rules: typing.List[typing.List[str]]):
        """
        新增policies
        namespace: 命名空间
        sec: 表示策略中的"区段”，通常为"p”或"g”，分别表示策略和角色
        ptype: 表示策略的类型，例如“p”表示访问控制策路，“g"表示角色管理策略。
        rules: policy的数组
        res:
        {"success": True, "data": rules}
        会返回新增成功的rules数据
        """
        res = casin_server.add_policies(ns=namespace, sec=sec, ptype=ptype, rules=rules)
        return res

    @classmethod
    def remove_policies(cls, namespace: str, sec: str, ptype: str, rules: typing.List[typing.List[str]]):
        """
        删除指定的policies
        namespace: 命名空间
        sec: 表示策略中的"区段”，通常为"p”或"g”，分别表示策略和角色
        ptype: 表示策略的类型，例如“p”表示访问控制策路，“g"表示角色管理策略。
        rules: policy的数组
        res:
        {"success": True, "data": rules}
        会返回删除成功的rules数据
        """
        res = casin_server.remove_policies(ns=namespace, sec=sec, ptype=ptype, rules=rules)
        return res

    @classmethod
    def remove_filter_policies(cls, namespace: str, sec: str, ptype: str, field_index: int,
                               field_values: typing.List[str]):
        """
        删除指定的policies
        namespace: 命名空间
        sec: 表示策略中的"区段”，通常为"p”或"g”，分别表示策略和角色
        ptype: 表示策略的类型，例如“p”表示访问控制策路，“g"表示角色管理策略。
        field_index: 过滤policy的数组字段的下标
        field_values: 过滤policy的值
        res:
        {"success": True, "data": rules}
        会返回删除成功的rules数据
        """
        res = casin_server.remove_filter_policies(ns=namespace, sec=sec, ptype=ptype, fieldIndex=field_index,
                                                  fieldValues=field_values)
        return res
