from django.core.cache import cache

from apps.syslog.constants import BK_CLOUD_ID, BK_PROPERTY_NAME
from blueking.component.client import BaseComponentClient
from common.performance import fn_performance
from utils import constants, exceptions
from utils.app_log import logger
from utils.decorators import get_all_page


class BkApiCCUtils(object):
    """蓝鲸配置平台接口管理"""

    @staticmethod
    def search_object_attribute(client: BaseComponentClient, bk_obj_id: str = None, bk_biz_id: int = None, **kwargs):

        if bk_obj_id:
            kwargs["bk_obj_id"] = bk_obj_id
        if bk_biz_id:
            kwargs["bk_biz_id"] = bk_biz_id
        resp = client.cc.search_object_attribute(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_object_attribute-获取对象属性出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("获取对象属性出错, 详情: %s" % resp["message"])

        object_attributes = resp["data"]
        # 修改字段属性为必填，方便在创建主机时使用
        for q in object_attributes:
            bk_property_name = q.get("bk_property_name")
            if bk_property_name in BK_PROPERTY_NAME:
                q.update(isrequired=True)
            if bk_property_name == BK_CLOUD_ID:
                q["bk_property_type"] = "int"

        return object_attributes

    @classmethod
    def search_inst(cls, client: BaseComponentClient, bk_obj_id: str = None, **kwargs):
        """根据关联关系实例查询模型实例"""
        kwargs.update(bk_obj_id=bk_obj_id)
        return cls.cc_search_inst(client, kwargs)

    @staticmethod
    def search_business(client: BaseComponentClient, **kwargs):
        resp = client.cc.search_business(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_business-查询业务出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"]
        return search_object_instances

    @staticmethod
    def update_business(client: BaseComponentClient, **kwargs):
        if kwargs["bk_biz_id"] == 2 and "bk_biz_name" in kwargs:
            kwargs["data"].pop("bk_biz_name")
        resp = client.cc.update_business(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_business-更新业务出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新业务出错, 详情: %s" % resp.get("message", ""))

    @staticmethod
    def search_inst_asst_object_inst_base_info(
        client: BaseComponentClient, bk_obj_id, bk_inst_id, association_obj_id="host", is_target_object=False, **kwargs
    ):
        asst_insts = cache.get(f"ass_insts_{bk_obj_id}_{bk_inst_id}_{is_target_object}")
        if asst_insts:
            return 0, asst_insts

        """根据模型对象获取关联的对象"""
        condition = {
            "bk_obj_id": bk_obj_id,
            "bk_inst_id": bk_inst_id,
            "association_obj_id": association_obj_id,
            "is_target_object": is_target_object,
        }
        kwargs.update(condition=condition)
        resp = client.cc.search_inst_asst_object_inst_base_info(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_inst_asst_object_inst_base_info-根据模型对象获取关联的主机对象出错, 详情: %s" % resp)
            raise exceptions.GetDateError("根据模型对象获取关联的主机对象出错, 详情: %s" % resp.get("message", ""))

        ass_insts = resp["data"]["info"] or []
        count = resp["data"]["count"]
        cache.set(f"ass_insts_{bk_obj_id}_{bk_inst_id}_{is_target_object}", ass_insts, constants.DEFAULT_CACHE_TTL)

        return count, ass_insts

    @classmethod
    @fn_performance
    def list_biz_hosts(cls, client, bk_biz_id, **kwargs):
        """查询业务下主机"""
        page_info = {"start": 0, "limit": constants.BK_CC_BIZ_HOSTS_LIMIT_NUMBER, "sort": "bk_host_id"}
        kwargs.update(page=page_info, bk_biz_id=bk_biz_id)
        return cls.cc_list_biz_hosts(client, kwargs)

    @staticmethod
    def cc_list_biz_hosts(client, kwargs):
        resp = client.cc.list_biz_hosts(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_biz_hosts-查询业务下主机出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务下主机出错, 详情: %s" % resp.get("message", ""))
        hosts = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, hosts

    @staticmethod
    @fn_performance
    def get_biz_host_by_all_bizs(client):
        """获取所有业务的主机mapping"""
        bk_biz_ids = [i["bk_biz_id"] for i in BkApiCCUtils.search_business(client, fields=["bk_biz_id"])]
        biz_hosts_mapping = {}
        for bk_biz_id in bk_biz_ids:
            _, hosts = BkApiCCUtils.list_biz_hosts_v2(
                client, **dict(bk_biz_id=bk_biz_id, page=dict(start=0, limit=-1, sort=""))
            )
            biz_hosts_mapping[bk_biz_id] = hosts
        cache.set("all_biz_hosts", biz_hosts_mapping, constants.DEFAULT_CACHE_TTL)
        return biz_hosts_mapping

    @staticmethod
    @fn_performance
    def get_biz_hosts(client, bk_biz_id):
        """获取业务下主机"""
        all_biz_hosts = cache.get("all_biz_hosts")
        if all_biz_hosts:
            biz_hosts = all_biz_hosts.pop(bk_biz_id, None)
            if biz_hosts is None:
                _, biz_hosts = BkApiCCUtils.list_biz_hosts_v2(
                    client, **dict(bk_biz_id=bk_biz_id, page=dict(start=0, limit=-1, sort=""))
                )
                all_biz_hosts[bk_biz_id] = biz_hosts
                cache.set("all_biz_hosts", all_biz_hosts, constants.DEFAULT_CACHE_TTL)
                return biz_hosts
            return biz_hosts
        all_biz_hosts = BkApiCCUtils.get_biz_host_by_all_bizs(client)
        return all_biz_hosts.get(bk_biz_id, [])

    @staticmethod
    @fn_performance
    def search_biz_inst_topo(client: BaseComponentClient, bk_biz_id: int, level=-1):
        """获取业务实例拓扑"""
        query_dict = dict(bk_username=client, bk_biz_id=bk_biz_id, level=level)
        resp = client.cc.search_biz_inst_topo(query_dict)
        if not resp["result"]:
            logger.exception("配置平台-search_biz_inst_topo-获取业务实例拓扑出错, 详情: %s" % resp["message"])
            raise exceptions.GetDateError("获取业务实例拓扑出错, 详情: %s" % resp["message"])
        return resp["data"][0] if resp["data"] else {}

    @staticmethod
    def list_operation_audit(client: BaseComponentClient, **kwargs):
        """获取操作审计列表"""
        resp = client.cc.list_operation_audit(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_operation_audit-获取操作审计列表出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取操作审计列表出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, search_object_instances

    @staticmethod
    def find_audit_by_id(client: BaseComponentClient, ids):
        """获取操作审计详情"""
        is_one = False
        if isinstance(ids, int):
            ids = [ids]
            is_one = True
        if not isinstance(ids, (list, tuple, set)):
            raise TypeError("类型不支持")
        resp = client.cc.find_audit_by_id(id=ids)
        if not resp["result"]:
            logger.exception("配置平台-find_audit_by_id-获取操作审计详情出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取操作审计详情出错, 详情: %s" % resp.get("message", ""))
        audit_details = resp["data"]
        if is_one:
            return audit_details[0] if audit_details else None
        return audit_details

    @staticmethod
    def find_host_biz_relations(client: BaseComponentClient, bk_host_ids):
        """查找主机的业务关系"""
        resp = client.cc.find_host_biz_relations(bk_host_id=bk_host_ids)
        if not resp["result"]:
            logger.exception("配置平台-find_host_biz_relations-查找主机的业务关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查找主机的业务关系出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @fn_performance
    def search_related_inst_asso(client, **kwargs):
        """查询某实例所有的关联关系"""
        page_info = {"start": 0, "limit": constants.BK_CC_BIZ_HOSTS_LIMIT_NUMBER}
        kwargs.update(page=page_info)
        resp = client.cc.search_related_inst_asso(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_related_inst_asso-查询某实例所有的关联关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询某实例所有的关联关系出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @fn_performance
    def delete_related_inst_asso(client, kwargs):
        """根据实例关联关系的ID删除实例之间的关联"""
        resp = client.cc.delete_related_inst_asso(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_related_inst_asso-根据实例关联关系的ID删除实例之间的关联出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("根据实例关联关系的ID删除实例之间的关联出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @fn_performance
    def batch_update_host(client, **kwargs):
        """根据主机ID查询业务相关信息"""
        resp = client.cc.batch_update_host(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-batch_update_host-批量更新主机属性出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("批量更新主机属性出错, 详情: %s" % resp.get("message", ""))

    @classmethod
    @get_all_page(constants.LIST_BIZ_HOSTS_MAX_NUM)
    @fn_performance
    def list_biz_hosts_v2(cls, client, **kwargs):
        """查询业务下主机"""
        return cls.cc_list_biz_hosts(client, kwargs)

    @staticmethod
    @get_all_page(constants.LIST_BIZ_HOSTS_MAX_NUM)
    @fn_performance
    def find_host_by_topo_v2(client, **kwargs):
        """查询拓扑节点下的主机"""
        resp = client.cc.find_host_by_topo(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_host_by_topo-查询拓扑节点下的主机出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询拓扑节点下的主机出错, 详情: %s" % resp.get("message", ""))
        hosts = resp["data"]["info"]
        count = resp["data"]["count"]

        return count, hosts

    @staticmethod
    @get_all_page(constants.LIST_BIZ_HOSTS_MAX_NUM)
    @fn_performance
    def list_hosts_without_biz_v2(client, **kwargs):
        """没有业务信息的主机查询"""
        resp = client.cc.list_hosts_without_biz(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_hosts_without_biz-查询业务下主机出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务下主机出错, 详情: %s" % resp.get("message", ""))
        hosts = resp["data"]["info"]
        count = resp["data"]["count"]

        return count, hosts

    @staticmethod
    @fn_performance
    def search_related_inst_asso_v2(client, **kwargs):
        """查询某实例所有的关联关系"""
        resp = client.cc.search_related_inst_asso(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_related_inst_asso-查询某实例所有的关联关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询某实例所有的关联关系出错, 详情: %s" % resp.get("message", ""))
        hosts = resp["data"]

        return hosts

    @classmethod
    @get_all_page(constants.SEARCH_INST_MAX_NUM)
    def search_inst_v2(cls, client, **kwargs):
        """根据关联关系实例查询模型实例"""
        return cls.cc_search_inst(client, kwargs)

    @staticmethod
    def cc_search_inst(client, kwargs):
        resp = client.cc.search_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_inst-获取实例出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取实例出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"] or []
        count = resp["data"]["count"]
        return count, search_object_instances

    @staticmethod
    @get_all_page(constants.SEARCH_INST_MAX_NUM)
    def search_inst_topo_v2(client, **kwargs):
        resp = client.cc.search_inst_topo(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_inst_topo-获取实例出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取实例出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"] or []
        count = resp["data"]["count"]
        return count, search_object_instances

    @staticmethod
    @fn_performance
    def find_host_biz_relations_v2(client, **kwargs):
        """根据主机ID查询业务相关信息"""
        resp = client.cc.find_host_biz_relations(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_host_biz_relations-根据主机ID查询业务相关信息出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("根据主机ID查询业务相关信息出错, 详情: %s" % resp.get("message", ""))
        hosts = resp["data"]

        return hosts

    @staticmethod
    @fn_performance
    def search_objects_v2(client, bk_classification_id=None, include_ispaused=False, **kwargs):
        """查询模型"""
        if bk_classification_id:
            kwargs.update(bk_classification_id=bk_classification_id)

        # 过滤隐藏模型
        kwargs.update(bk_ishidden=False)

        # 不包含停用模型，加过滤条件
        if not include_ispaused:
            kwargs.update(bk_ispaused=False)

        resp = client.cc.search_objects(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_objects-查询实例出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询实例出错, 详情: %s" % resp.get("message", ""))

        return resp["data"]

    @staticmethod
    @fn_performance
    def batch_update_host_v2(client, **kwargs):
        """批量更新主机属性"""
        resp = client.cc.batch_update_host(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-batch_update_host-更新主机属性出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新主机属性出错, 详情: %s" % resp.get("message", ""))

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    @fn_performance
    def search_business_v2(client: BaseComponentClient, **kwargs):
        """查询业务"""
        resp = client.cc.search_business(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_business-查询业务出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, search_object_instances

    @staticmethod
    @get_all_page(constants.LIST_OPERATION_AUDIT_MAX_NUM)
    @fn_performance
    def list_operation_audit_v2(client, **kwargs):
        """获取操作审计日志"""
        resp = client.cc.list_operation_audit(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_operation_audit-获取操作审计日志出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取操作审计日志出错, 详情: %s" % resp.get("message", ""))
        data_list = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, data_list

    @staticmethod
    @fn_performance
    def get_host_base_info(client, **kwargs):
        """获取主机详情"""
        resp = client.cc.get_host_base_info(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-get_host_base_info-获取主机详情出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取主机详情出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def find_object_association(client, **kwargs):
        """查询模型的实例之间的关联关系"""
        resp = client.cc.find_object_association(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_object_association-查询模型的实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询模型的实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_object_attribute(client, **kwargs):
        """创建模型属性"""
        resp = client.cc.create_object_attribute(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-create_object_attribute-创建失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_object_attribute(client, **kwargs):
        """删除对象模型属性"""
        resp = client.cc.delete_object_attribute(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_object_attribute-删除失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_object_attribute(client, **kwargs):
        """修改模型属性"""
        resp = client.cc.update_object_attribute(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_object_attribute-修改失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("修改失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def search_object_attribute_v2(client, **kwargs):
        """查询模型属性"""
        resp = client.cc.search_object_attribute(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_object_attribute-查询型属性出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询型属性出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def get_biz_internal_module(client, **kwargs):
        """查询业务下空闲机池"""
        resp = client.cc.get_biz_internal_module(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-get_biz_internal_module-查询业务下空闲机池出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务下空闲机池出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_inst(client, **kwargs):
        """创建实例"""
        data = dict(
            bk_biz_id=kwargs["bk_biz_id"],
            bk_obj_id=kwargs["bk_obj_id"],
            bk_parent_id=kwargs["bk_parent_id"],
            **kwargs["obj_attr"],
        )
        resp = client.cc.create_inst(data)
        if not resp["result"]:
            logger.exception("配置平台-create_inst-创建失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_inst_v2(client, **kwargs):
        """创建实例v2"""
        resp = client.cc.create_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-create_inst_v2-创建失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_set(client, **kwargs):
        """创建集群"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "data": dict(bk_parent_id=kwargs["bk_parent_id"], **kwargs["obj_attr"]),
        }
        resp = client.cc.create_set(data)
        if not resp["result"]:
            logger.exception("配置平台-create_set-创建失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_module(client, **kwargs):
        """创建模块"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "bk_set_id": kwargs["bk_parent_id"],
            "data": dict(bk_parent_id=kwargs["bk_parent_id"], **kwargs["obj_attr"]),
        }
        resp = client.cc.create_module(data)
        if not resp["result"]:
            logger.exception("配置平台-create_module-创建失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_inst(client, **kwargs):
        """删除实例"""
        data = {
            "bk_obj_id": kwargs["bk_obj_id"],
            "bk_inst_id": kwargs["bk_node_id"],
        }
        bk_biz_id = kwargs.get("bk_biz_id")
        if bk_biz_id:
            data["bk_biz_id"] = bk_biz_id

        resp = client.cc.delete_inst(data)
        if not resp["result"]:
            logger.exception("配置平台-delete_inst-删除失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_inst_v2(client, **kwargs):
        """删除实例v2"""
        resp = client.cc.delete_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_inst_v2-删除失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_set(client, **kwargs):
        """删除集群"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "bk_obj_id": kwargs["bk_obj_id"],
            "bk_set_id": kwargs["bk_node_id"],
        }
        resp = client.cc.delete_set(data)
        if not resp["result"]:
            logger.exception("配置平台-delete_set-删除失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_module(client, **kwargs):
        """删除模块"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "bk_obj_id": kwargs["bk_obj_id"],
            "bk_set_id": kwargs["bk_parent_id"],
            "bk_module_id": kwargs["bk_node_id"],
        }
        resp = client.cc.delete_module(data)
        if not resp["result"]:
            logger.exception("配置平台-delete_module-删除失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_inst(client, **kwargs):
        """修改实例"""
        data = dict(
            bk_biz_id=kwargs["bk_biz_id"],
            bk_obj_id=kwargs["bk_obj_id"],
            bk_inst_id=kwargs["bk_node_id"],
            **kwargs["obj_attr"],
        )
        resp = client.cc.update_inst(data)
        if not resp["result"]:
            logger.exception("配置平台-update_inst-修改实例出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("修改实例出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_set(client, **kwargs):
        """更新集群"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "bk_set_id": kwargs["bk_node_id"],
            "data": dict(**kwargs["obj_attr"]),
        }
        resp = client.cc.update_set(data)
        if not resp["result"]:
            logger.exception("配置平台-update_set-更新集群出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新集群出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_module(client, **kwargs):
        """更新模块"""
        data = {
            "bk_biz_id": kwargs["bk_biz_id"],
            "bk_set_id": kwargs["bk_parent_id"],
            "bk_module_id": kwargs["bk_node_id"],
            "data": dict(**kwargs["obj_attr"]),
        }
        resp = client.cc.update_module(data)
        if not resp["result"]:
            logger.exception("配置平台-update_module-更新模块出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新模块出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_biz(client: BaseComponentClient, **kwargs):
        if kwargs["bk_biz_id"] == 2 and "bk_biz_name" in kwargs["obj_attr"]:
            kwargs["obj_attr"].pop("bk_biz_name")
        data = {"bk_biz_id": kwargs["bk_biz_id"], "data": dict(**kwargs["obj_attr"])}
        resp = client.cc.update_business(data)
        if not resp["result"]:
            logger.exception("配置平台-update_business-更新业务出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新业务出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def transfer_host_module(client, **kwargs):
        """业务内主机转移模块"""
        resp = client.cc.transfer_host_module(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-transfer_host_module-业务内主机转移模块出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("业务内主机转移模块出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def transfer_host_to_idlemodule(client, **kwargs):
        """上交主机到业务的空闲机模块"""
        resp = client.cc.transfer_host_to_idlemodule(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-transfer_host_to_idlemodule-上交主机到业务的空闲机模块出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("上交主机到业务的空闲机模块出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def transfer_host_to_resourcemodule(client, **kwargs):
        """上交主机至资源池"""
        resp = client.cc.transfer_host_to_resourcemodule(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-transfer_host_to_resourcemodule-上交主机至资源池出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("上交主机至资源池出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def transfer_resourcehost_to_idlemodule(client, **kwargs):
        """资源池主机分配至业务的空闲机模块"""
        resp = client.cc.transfer_resourcehost_to_idlemodule(kwargs)
        if not resp["result"]:
            logger.exception(
                "配置平台-transfer_resourcehost_to_idlemodule-资源池主机分配至业务的空闲机模块出错, 详情: %s" % resp.get("message", "")
            )
            raise exceptions.GetDateError("资源池主机分配至业务的空闲机模块出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def find_instance_association(client, **kwargs):
        """查询模型实例之间的关联关系"""
        if not kwargs.get("bk_obj_id"):
            bk_obj_id = kwargs.get("condition", {}).get("bk_obj_id")
            if bk_obj_id:
                kwargs.update(bk_obj_id=bk_obj_id)
        resp = client.cc.find_instance_association(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_instance_association-查询模型实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询模型实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_instance_association(client, **kwargs):
        """删除模型实例之间的关系"""
        resp = client.cc.delete_instance_association(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_instance_association-删除模型实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除模型实例之间的关联关系出错, 详情: %s" % resp.get("message", ""))
        return True

    @staticmethod
    def search_business_biz_list(biz_list):
        from blueapps.utils import get_client_by_user

        client = get_client_by_user("admin")
        kwargs = {"fields": ["bk_biz_id", "bk_biz_name"], "condition": {"bk_biz_id": {"$in": biz_list}}}
        resp = client.cc.search_business(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_business-查询业务出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务出错, 详情: %s" % resp.get("message", ""))
        search_object_instances = resp["data"]["info"]
        return search_object_instances

    @staticmethod
    def search_classifications(client, **kwargs):
        """查询模型分类"""
        resp = client.cc.search_classifications(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_classifications-查询模型分类出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询模型分类出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_classification(client, **kwargs):
        """创建模型分类"""
        resp = client.cc.create_classification(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_classification-创建模型分类出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建模型分类出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_classification(client, **kwargs):
        """更新模型分类"""
        resp = client.cc.update_classification(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_classification-更新模型分类出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新模型分类出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_classification(client, **kwargs):
        """删除模型分类"""
        resp = client.cc.delete_classification(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_classification-删除模型分类出错, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除模型分类出错, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_object(client, **kwargs):
        """创建模型"""
        resp = client.cc.create_object(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-create_object-创建模型失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建模型失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def add_instance_association(client, **kwargs):
        """创建模型"""
        resp = client.cc.add_instance_association(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-add_instance_association-新增模型实例之间的关联关系失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("新增模型实例之间的关联关系失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_object(client, **kwargs):
        """删除模型"""
        resp = client.cc.delete_object(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_object-删除模型失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除模型失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_object(client, **kwargs):
        """修改模型"""
        resp = client.cc.update_object(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_object-修改模型失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("修改模型失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def list_service_instance(client, **kwargs):
        """查询服务实例列表"""
        resp = client.cc.list_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_service_instance-查询服务实例列表失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询服务实例列表失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    def list_service_instance_v2(client, **kwargs):
        """查询服务实例列表"""
        resp = client.cc.list_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_service_instance-查询服务实例列表失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询服务实例列表失败, 详情: %s" % resp.get("message", ""))
        items = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, items

    @staticmethod
    def list_service_instance_by_host(client, **kwargs):
        """通过主机查询关联的服务实例列表"""
        resp = client.cc.list_service_instance_by_host(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_service_instance_by_host-通过主机查询关联的服务实例列表失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("通过主机查询关联的服务实例列表失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def list_service_instance_detail(client, **kwargs):
        """获取服务实例详细信息"""
        resp = client.cc.list_service_instance_detail(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_service_instance_detail-获取服务实例详细信息失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取服务实例详细信息失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_service_instance(client, **kwargs):
        """创建服务实例"""
        resp = client.cc.create_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-create_service_instance-创建服务实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建服务实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_service_instance(client, **kwargs):
        """删除服务实例"""
        resp = client.cc.delete_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_service_instance-删除服务实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除服务实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_service_instance(client, **kwargs):
        """更新服务实例"""
        resp = client.cc.update_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_service_instance-更新服务实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新服务实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def add_label_for_service_instance(client, **kwargs):
        """服务实例添加标签"""
        resp = client.cc.add_label_for_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-add_label_for_service_instance-服务实例添加标签失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("服务实例添加标签失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def remove_label_from_service_instance(client, **kwargs):
        """从服务实例移除标签"""
        resp = client.cc.remove_label_from_service_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-remove_label_from_service_instance-从服务实例移除标签失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("从服务实例移除标签失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def list_process_instance(client, **kwargs):
        """查询进程实例列表"""
        resp = client.cc.list_process_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_process_instance-查询进程实例列表失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询进程实例列表失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def list_process_detail_by_ids(client, **kwargs):
        """查询某业务下进程ID对应的进程详情"""
        resp = client.cc.list_process_detail_by_ids(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-list_process_detail_by_ids-查询某业务下进程ID对应的进程详情失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询某业务下进程ID对应的进程详情失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def create_process_instance(client, **kwargs):
        """创建进程实例"""
        resp = client.cc.create_process_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-create_process_instance-创建进程实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("创建进程实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def delete_process_instance(client, **kwargs):
        """删除进程实例"""
        resp = client.cc.delete_process_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-delete_process_instance-删除进程实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("删除进程实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_process_instance(client, **kwargs):
        """更新进程实例"""
        resp = client.cc.update_process_instance(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_process_instance-更新进程实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("更新进程实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def get_mainline_object_topo(client, **kwargs):
        """查询主线模型的业务拓扑"""
        resp = client.cc.get_mainline_object_topo(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-get_mainline_object_topo-查询主线模型的业务拓扑失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询主线模型的业务拓扑失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    def find_module_with_relation(client, **kwargs):
        """查询业务下的模块"""
        resp = client.cc.find_module_with_relation(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_module_with_relation-查询业务下的模块失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询业务下的模块失败, 详情: %s" % resp.get("message", ""))
        items = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, items

    @staticmethod
    def batch_delete_inst(client, **kwargs):
        """批量删除对象实例"""
        resp = client.cc.batch_delete_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-batch_delete_inst-批量删除对象实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("批量删除对象实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def batch_create_inst(client, **kwargs):
        """批量创建对象实例"""
        resp = client.cc.batch_create_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-batch_delete_inst-批量创建对象实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("批量创建对象实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def batch_create_instance_association(client, **kwargs):
        """批量创建模型实例之间的关联关系"""
        resp = client.cc.batch_create_instance_association(kwargs)
        if not resp["result"]:
            logger.exception(
                "配置平台-batch_create_instance_association-批量创建模型实例之间的关联关系失败, 详情: %s" % resp.get("message", "")
            )
            raise exceptions.GetDateError("批量创建模型实例之间的关联关系失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def batch_delete_host(client, bk_host_ids: list):
        """批量删除对象实例"""
        resp = client.cc.delete_host(dict(bk_host_id=",".join(str(i) for i in bk_host_ids)))
        if not resp["result"]:
            logger.exception("配置平台-batch_delete_host-批量删除主机实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("批量删除主机实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def update_business_enable_status(client, **kwargs):
        """修改业务启用状态"""
        kwargs.update(bk_supplier_account="0")
        resp = client.cc.update_business_enable_status(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-update_business_enable_status-修改业务启用状态失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("修改业务启用状态失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def add_host_to_resource(client, **kwargs):
        """新增主机到资源池"""
        resp = client.cc.add_host_to_resource(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-add_host_to_resource-新增主机到资源池失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("新增主机到资源池失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def search_inst_by_object(client, **kwargs):
        """查询实例详情"""
        resp = client.cc.search_inst_by_object(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_inst_by_object-查询实例详情失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询实例详情失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    def batch_update_inst(client, **kwargs):
        """批量修改实例"""
        resp = client.cc.batch_update_inst(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-batch_update_inst-批量更新通用对象实例失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("批量更新通用对象实例失败, 详情: %s" % resp.get("message", ""))
        return resp["data"]

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    def find_host_topo_relation(client, **kwargs):
        """获取主机与拓扑的关系"""
        resp = client.cc.find_host_topo_relation(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-find_host_topo_relation-获取主机与拓扑的关系失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("获取主机与拓扑的关系失败, 详情: %s" % resp.get("message", ""))
        items = resp["data"]["data"]
        count = resp["data"]["count"]
        return count, items

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    def search_set(client, **kwargs):
        """查询集群"""
        resp = client.cc.search_set(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_set-查询集群失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询集群失败, 详情: %s" % resp.get("message", ""))
        items = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, items

    @staticmethod
    @get_all_page(constants.SEARCH_BUSINESS_MAX_NUM)
    def search_cloud_area(client, **kwargs):
        """查询集群"""
        resp = client.cc.search_cloud_area(kwargs)
        if not resp["result"]:
            logger.exception("配置平台-search_cloud_area-查询云区域失败, 详情: %s" % resp.get("message", ""))
            raise exceptions.GetDateError("查询云区域失败, 详情: %s" % resp.get("message", ""))
        items = resp["data"]["info"]
        count = resp["data"]["count"]
        return count, items
