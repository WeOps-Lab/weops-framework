# -- coding: utf-8 --

# @File : casbin_inst_service.py
# @Time : 2023/7/19 17:47
# @Author : windyzhao
from apps.system_mgmt.casbin_package.cabin_inst_rbac import INST_NAMESPACE
from apps.system_mgmt.constants import ALL_INST_PERMISSIONS_OBJ, BASIC_MONITOR, BASIC_MONITOR_POLICY, NOT_BASIC_MONITOR
from apps.system_mgmt.models import InstancesPermissions, SysRole
from common.casbin_mesh_common import CasbinMeshApiServer
from utils.app_log import logger


class CasBinInstService(object):
    @classmethod
    def get_instance_type_instance(cls, instance_type, inst_ids, bk_obj_id=None):
        """
        bk_obj_id只能是 NOT_BASIC_MONITOR 里的
        """
        permissions_filter = {"instance_type": instance_type}
        if bk_obj_id:
            permissions_filter["permissions__contains"] = {"bk_obj_id": bk_obj_id}
        instances = InstancesPermissions.objects.filter(**permissions_filter)
        for instance in instances:
            _bk_obj_id = instance.permissions.get("bk_obj_id")
            if bk_obj_id and bk_obj_id != _bk_obj_id:
                continue
            _instances = []
            for inst_id in instance.instances:
                if str(inst_id) not in inst_ids:
                    _instances.append(inst_id)
            instance.instances = _instances

        InstancesPermissions.objects.bulk_update(instances, fields=["instances"], batch_size=100)

    @classmethod
    def get_user_instances(cls, username, instance_type, bk_obj_id=None, view=True, manage=False, use=False) -> list:
        """
        根据用户名称和实例类型
        返回对应的inst_id的list
        username: 用户名称
        instance_type: 实例类型
        实例类型目前有六种，详情请全局搜索 INSTANCE_TYPES
        """
        result = set()
        permissions_filter = {"view": view}
        if manage:
            permissions_filter["manage"] = True
        if use:
            permissions_filter["use"] = True
        if bk_obj_id:
            permissions_filter["bk_obj_id"] = bk_obj_id

        instances = InstancesPermissions.objects.filter(
            instance_type=instance_type, role__sysuser__bk_username=username, permissions__contains=permissions_filter
        )
        for instance in instances.values("id", "instances"):
            result.update(set(instance["instances"]))

        return list(result)

    @classmethod
    def operator_polices(cls, data):
        result = []
        instances = data["instances"]
        role_name = SysRole.objects.get(id=data["role"]).role_name
        for per, per_v in data["permissions"].items():
            if not per_v:
                continue
            for instance_id in instances:
                bk_obj_id = cls.get_bk_obj_id(data)
                instance_type = f"{data['instance_type']}{bk_obj_id}"
                policy = [role_name, instance_type, per, str(instance_id), str(data["id"])]
                result.append(policy)

        return result

    @classmethod
    def get_bk_obj_id(cls, data):
        bk_obj_id = data["permissions"].get("bk_obj_id", "")
        if bk_obj_id:
            if data["instance_type"] == "监控采集":
                if bk_obj_id not in NOT_BASIC_MONITOR:
                    bk_obj_id = BASIC_MONITOR
            else:
                if bk_obj_id != "log":
                    bk_obj_id = BASIC_MONITOR_POLICY

        return bk_obj_id

    @classmethod
    def create_policies(cls, policies, sec, ptype):
        res = CasbinMeshApiServer.add_policies(namespace=INST_NAMESPACE, sec=sec, ptype=ptype, rules=policies)
        logger.info("新增polices，结果:{}".format(res["success"]))
        return res["success"]

    @classmethod
    def remove_filter_policies(cls, sec, ptype, field_index, field_values):
        res = CasbinMeshApiServer.remove_filter_policies(
            namespace=INST_NAMESPACE, sec=sec, ptype=ptype, field_index=field_index, field_values=[str(field_values)]
        )
        logger.info("删除polices，结果:{}".format(res["success"]))
        return res["success"]

    @classmethod
    def remove_inst_ids(cls, policies):
        """
        监控采集basic_monitor -->
        instance_type=监控采集
        bk_obj_id: 只能有 NOT_BASIC_MONITOR 这些
        其余都为空
        """

        bk_obj_id = ""
        instance_type = ""
        inst_ids = set()
        for _, _instance_type, operator, inst_id, _ in policies:
            inst_ids.add(inst_id)
            instance_type = _instance_type
            for _inst_obj in ALL_INST_PERMISSIONS_OBJ:
                if _instance_type.endswith(_inst_obj):
                    instance_type = _instance_type.replace(_inst_obj, "")
                    if _inst_obj in NOT_BASIC_MONITOR:
                        bk_obj_id = _inst_obj
                    continue
        cls.get_instance_type_instance(instance_type, inst_ids, bk_obj_id=bk_obj_id)

    @classmethod
    def remove_policies(cls, policies, sec, ptype):
        res = CasbinMeshApiServer.remove_policies(namespace=INST_NAMESPACE, sec=sec, ptype=ptype, rules=policies)
        logger.info("remove_policies删除polices，结果:{}".format(res["success"]))
        if policies and res["success"]:
            cls.remove_inst_ids(policies)
        return res["success"]
