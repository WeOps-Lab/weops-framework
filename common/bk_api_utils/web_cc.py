import requests
from django.conf import settings

from blueapps.core.exceptions import ServerBlueException
from utils.app_log import logger


def search_host_almighty(cookies, data):
    """查询主机接口"""

    url = f"{settings.CMDB_URL}api/v3/hosts/search"
    resp = requests.post(url, cookies=cookies, json=data, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-查询主机失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"查询主机失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def get_unique_attrs(cookies, bk_obj_id):
    """查询模型唯一属性"""
    url = f"{settings.CMDB_URL}api/v3/find/objectunique/object/{bk_obj_id}"
    resp = requests.post(url, cookies=cookies, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-查询模型唯一属性失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"查询模型唯一属性失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def create_unique_attrs(cookies, bk_obj_id, key_ids):
    """创建模型唯一属性"""
    url = f"{settings.CMDB_URL}api/v3/create/objectunique/object/{bk_obj_id}"
    data = {
        "must_check": False,
        "keys": [{"key_kind": "property", "key_id": i} for i in key_ids],
    }
    resp = requests.post(url, cookies=cookies, json=data, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-创建模型唯一属性失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"创建模型唯一属性失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def delete_unique_attrs(cookies, bk_obj_id, key_id):
    """删除模型唯一属性"""
    url = f"{settings.CMDB_URL}api/v3/delete/objectunique/object/{bk_obj_id}/unique/{key_id}"
    resp = requests.post(url, cookies=cookies, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-删除模型唯一属性失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"删除模型唯一属性失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def create_object_association(cookies, data):
    """创建模型关联关系"""
    url = f"{settings.CMDB_URL}api/v3/create/objectassociation"
    resp = requests.post(url, cookies=cookies, json=data, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-创建模型关联关系失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"创建模型关联关系失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def update_service_inst(cookies, bk_biz_id, data):
    """修改服务实例"""
    url = f"{settings.CMDB_URL}api/v3/updatemany/proc/service_instance/biz/{bk_biz_id}"
    resp = requests.put(url, cookies=cookies, json=data, verify=False).json()
    if not resp["result"]:
        raise ServerBlueException(f"配置平台-修改服务实例失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def update_object_association(cookies, association_id, data):
    """修改模型关联关系"""
    url = f"{settings.CMDB_URL}api/v3/update/objectassociation/{association_id}"
    resp = requests.put(url, cookies=cookies, json=data, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-修改模型关联关系失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"修改模型关联关系失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def delete_object_association(cookies, association_id):
    """删除模型关联关系"""
    url = f"{settings.CMDB_URL}api/v3/delete/objectassociation/{association_id}"
    resp = requests.delete(url, cookies=cookies, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-删除模型关联关系失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"删除模型关联关系失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def create_group(cookies, data):
    """
    创建字段分组
    data: {
            "bk_group_id": "e83d6a7e-d54d-45fb-aa4e-360564d5e942",
            "bk_group_index": 3,
            "bk_group_name": "sasada13131",
            "bk_obj_id": "mongodb",
            "bk_supplier_account": "0",
            "is_collapse": false
        }
    """
    url = f"{settings.CMDB_URL}api/v3/create/objectattgroup"
    resp = requests.post(url, cookies=cookies, json=data, verify=False).json()
    return resp


def update_group(cookies, data):
    """
    修改字段分组
    data: {
            "condition": {
                "id": 106
            },
            "data": {
                "bk_group_name": "sasada13131121212",
                "is_collapse": false
            }
        }
    """
    url = f"{settings.CMDB_URL}api/v3/update/objectattgroup"
    resp = requests.put(url, cookies=cookies, json=data, verify=False).json()
    return resp


def delete_group(cookies, pk):
    """
    删除字段分组
    pk: 13
    """
    url = f"{settings.CMDB_URL}api/v3/delete/objectattgroup/{pk}"
    resp = requests.delete(url, cookies=cookies, verify=False).json()
    return resp


def find_association_type(cookies):
    """查询关联类型"""
    url = f"{settings.CMDB_URL}api/v3/find/associationtype"
    resp = requests.post(url, cookies=cookies, verify=False).json()
    if not resp["result"]:
        logger.exception("配置平台-查询关联类型失败, 详情: %s" % resp.get("bk_error_msg", ""))
        raise ServerBlueException(f"删除模型关联关系失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def list_process_instance_details(cookies, query_data):
    """查询进程下的实例"""
    url = f"{settings.CMDB_URL}api/v3/findmany/proc/process_instance/detail/by_ids"
    resp = requests.post(url, cookies=cookies, json=query_data, verify=False).json()
    if not resp["result"]:
        raise ServerBlueException(f"配置平台-查询进程下的实例失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def list_process_instance_by_module(cookies, query_data):
    """查询模块下进程实例列表"""
    url = f"{settings.CMDB_URL}api/v3/findmany/proc/process_instance/name_ids"
    resp = requests.post(url, cookies=cookies, json=query_data, verify=False).json()
    if not resp["result"]:
        raise ServerBlueException(f"配置平台-查询模块下进程实例列表失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def obj_attr_group_object(cookies, bk_obj_id):
    """查询模型分组"""
    url = f"{settings.CMDB_URL}api/v3/find/objectattgroup/object/{bk_obj_id}"
    resp = requests.post(url, cookies=cookies, verify=False).json()
    if not resp.get("result"):
        raise ServerBlueException(f"配置平台-查询模型分组失败！详情：{resp}")
    if not resp["result"]:
        raise ServerBlueException(f"配置平台-查询模型分组失败！详情：{resp['bk_error_msg']}")
    return resp["data"]


def objs_count(cookies, obj_ids):
    """查询模型实例数量, obj_ids最大数量为20"""
    url = f"{settings.CMDB_URL}object/count"
    resp = requests.post(url, cookies=cookies, json=dict(condition=dict(obj_ids=obj_ids)), verify=False).json()
    if not resp["result"]:
        raise ServerBlueException(f"配置平台-查询模型实例数量失败！详情：{resp['bk_error_msg']}")
    return resp["data"]
