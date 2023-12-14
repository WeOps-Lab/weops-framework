# -- coding: utf-8 --

# @File : casbin_mesh_api.py
# @Time : 2023/4/18 17:44
# @Author : windyzhao
"""
casbin_mesh的连接
做操作的依赖
"""
import requests
from django.conf import settings

from utils.app_log import logger


class ApiDefine(object):
    def __init__(self, path: str, method: str, description: str = ""):
        host = settings.CASBIN_MESH_HOST
        port = settings.CASBIN_MESH_PORT
        self.host = f"http://{host}:{port}"
        self.path = path
        self.headers = {}
        self.cookies = ""
        self.method = method
        self.description = description

    @property
    def total_url(self):
        return f"{self.host}{self.path}"

    def http_request(self, total_url, headers, cookies, params):
        try:
            resp = requests.request(
                self.method, total_url, headers=headers, params=params, cookies=cookies, json=params, verify=False
            )
        except Exception as e:
            logger.exception(f"请求地址[{total_url}]失败，请求方式[{self.method}]，异常原因[{e}]")
            return {"success": False, "data": None}

        if resp.status_code != requests.codes.OK:
            logger.exception("请求{}返回异常，请求参数:params【{}】, 状态码: {}".format(total_url, params, resp.status_code))
        try:
            req_data = resp.json()
        except Exception:
            msg = f""" 
            请求地址：{total_url}, 
            请求方式：{self.method}, 
            请求参数：params【{params}, 
            返回数据：{resp.text}, 
            失败原因：返回数据无法json化
            """  # noqa
            logger.exception(msg)
            req_data = None

        return {"success": resp.status_code == requests.codes.OK, "data": req_data}

    def __call__(self, **kwargs):
        url_params = kwargs.pop("url_params", {})
        params = {}
        params.update(kwargs)
        total_url = self.total_url.format(**url_params)
        return self.http_request(total_url, self.headers, self.cookies, params)  # noqa


class CasbinMeshOperation(object):
    """
    casbin_mesh
    目前全部使用POST请求
    数据体都是json
    """

    def __init__(self):
        self.enforce = ApiDefine("/enforce", "POST", description="权限鉴权")
        self.create_namespace = ApiDefine("/create/namespace", "POST", description="创建namespace")
        self.list_namespaces = ApiDefine("/list/namespaces", "POST", description="查询namespace")
        self.set_model = ApiDefine("/set/model", "POST", description="设置模型")
        self.list_model = ApiDefine("/print/model", "POST", description="查询模型")
        self.list_policies = ApiDefine("/list/policies", "POST", description="查询policy")
        self.add_policies = ApiDefine("/add/policies", "POST", description="新增多个policy")
        self.remove_policies = ApiDefine("/remove/policies", "POST", description="移除多个policy")
        self.remove_filter_policies = ApiDefine("/remove/filtered_policies", "POST", description="过滤移除多个policy")


casin_server = CasbinMeshOperation()
