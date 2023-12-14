import uuid

from blueking.component.shortcuts import get_client_by_user
from common.bk_api_utils.cc import BkApiCCUtils
from utils.thread_pool import ThreadPool


def get_biz_to_host_ids(task_id, client, bk_biz_id, bk_os_type):
    """根据业务id列表查询业务下主机，返回主机应用对应字典和业务下主机列表"""
    host_biz_dict = dict()
    bk_host_id_list = list()
    query_dict = dict(bk_biz_id=bk_biz_id, page=dict(start=0, limit=-1, sort=""), fields=["bk_host_id"])
    if bk_os_type:
        os_param = {"condition": "AND", "rules": [{"field": "bk_os_type", "operator": "equal", "value": bk_os_type}]}
        query_dict.update(host_property_filter=os_param)
    _, hosts = BkApiCCUtils.list_biz_hosts_v2(client, **query_dict)
    for host in hosts:
        bk_host_id_list.append(host["bk_host_id"])
        host_biz_dict[host["bk_host_id"]] = bk_biz_id
    return dict(task_id=task_id, data=[host_biz_dict, bk_host_id_list])


def get_host_id_list_by_biz_list(bk_biz_id_list, bk_os_type):
    """根据业务列表查询主机列表"""
    # 如果是业务时，构建业务列表，业务列表为空直接返回空列表
    if not bk_biz_id_list:
        return {}, []
    client = get_client_by_user("admin")
    # 查业务下主机ID
    pool = ThreadPool()
    for bk_biz_id in bk_biz_id_list:
        pool.add_task(get_biz_to_host_ids, str(uuid.uuid1()), client, bk_biz_id, bk_os_type)
    pool.wait_end()
    host_biz_dict, bk_host_id_list = {}, []
    for i in pool.get_result():
        _host_biz_dict, _bk_host_id_list = i
        host_biz_dict.update(_host_biz_dict)
        bk_host_id_list.extend(_bk_host_id_list)
    return host_biz_dict, bk_host_id_list


def get_obj_to_host_association(bk_obj_id, host_ids):
    """获取某个模型与主机模型实例的对应关系，并根据host列表进行过滤(即业务过滤)，再根据关联关系过滤"""
    condition = {
        "bk_obj_id": bk_obj_id,
        "bk_asst_obj_id": "host",
        "bk_asst_id": {"$in": ["install_on", "run"]},
        "bk_asst_inst_id": {"$in": host_ids},
    }
    resp = BkApiCCUtils.find_instance_association(get_client_by_user("admin"), condition=condition)
    result = {i["bk_inst_id"]: i["bk_asst_inst_id"] for i in resp}
    return result
