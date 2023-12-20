# -*- coding: utf-8 -*-
"""
celery 任务示例

本地启动celery命令: python  manage.py  celery  worker  --settings=settings
周期性任务还需要启动celery调度命令：python  manage.py  celerybeat --settings=settings
"""
import datetime
import typing

from celery import task
from celery.schedules import crontab
from celery.task import periodic_task

from apps.system_mgmt.casbin_package.cabin_inst_rbac import INST_NAMESPACE
from apps.system_mgmt.casbin_package.policy_constants import MESH_NAMESPACE
from apps.system_mgmt.constants import DB_APPS, DB_SUPER_USER
from apps.system_mgmt.models import SysApps
from apps.system_mgmt.utils import BizUtils, UserUtils
from apps.system_mgmt.common_utils.casbin_mesh_common import CasbinMeshApiServer
from utils.app_log import celery_logger as logger


@periodic_task(run_every=crontab(minute="0", hour="0", day_of_month="*"))
def pull_bk_user(*args, **kwargs):
    """拉取蓝鲸用户"""
    logger.info("pull bk_user task start, datetime={}".format(str(datetime.datetime.now())))
    UserUtils.pull_sys_user()
    logger.info("pull bk_user task finish datetime={}".format(str(datetime.datetime.now())))


@task
def update_biz(*args, **kwargs):
    """刷新业务"""
    # 获取业务权限id全部列表
    logger.info("pull update_biz task start")
    all_biz_list = BizUtils.get_all_biz_list()
    all_biz_ids = [i["bk_biz_id"] for i in all_biz_list]
    # 只更新超管的业务数据
    count = SysApps.objects.filter(app_key=DB_APPS, sys_role__role_name=DB_SUPER_USER).update(app_ids=all_biz_ids)
    logger.info(f"pull update_biz task finish update count:{count}")


@task
def sync_casbin_mesh_add_policies(sec: str, ptype: str, rules: typing.List[typing.List[str]]):
    """
    新增policies
    只做新增用户的policy
    新增具体policy请额外定义
    """
    res = CasbinMeshApiServer.add_policies(namespace=MESH_NAMESPACE, sec=sec, ptype=ptype, rules=rules)
    logger.info("异步新增polices到【{}】，结果:{}".format(MESH_NAMESPACE, res["success"]))

    res = CasbinMeshApiServer.add_policies(namespace=INST_NAMESPACE, sec=sec, ptype=ptype, rules=rules)
    logger.info("异步新增polices到【{}】，结果:{}".format(INST_NAMESPACE, res["success"]))


@task
def sync_casbin_mesh_remove_policies(sec: str, ptype: str, rules: typing.List[typing.List[str]]):
    """
    删除policies
    """
    res = CasbinMeshApiServer.remove_policies(namespace=MESH_NAMESPACE, sec=sec, ptype=ptype, rules=rules)
    logger.info("异步删除polices到【{}】，结果:{}".format(MESH_NAMESPACE, res["success"]))

    res = CasbinMeshApiServer.remove_policies(namespace=INST_NAMESPACE, sec=sec, ptype=ptype, rules=rules)
    logger.info("异步删除polices到【{}】，结果:{}".format(INST_NAMESPACE, res["success"]))


@task
def sync_casbin_mesh_remove_filter_policies(sec: str, ptype: str, field_index: int, field_values: typing.List[str]):
    """
    删除policies
    """
    res = CasbinMeshApiServer.remove_filter_policies(
        namespace=MESH_NAMESPACE, sec=sec, ptype=ptype, field_index=field_index, field_values=field_values
    )
    logger.info("异步删除polices，结果:{}".format(res["success"]))


@task
def sync_casbin_mesh_remove_add_policies(create_data, delete_data):
    """
    为了保持先后顺序
    """

    create_data["namespace"] = MESH_NAMESPACE
    delete_data["namespace"] = MESH_NAMESPACE

    res = CasbinMeshApiServer.remove_filter_policies(**delete_data)
    logger.info("异步删除polices，结果:{}".format(res["success"]))

    res = CasbinMeshApiServer.add_policies(**create_data)
    logger.info("异步新增polices，结果:{}".format(res["success"]))

