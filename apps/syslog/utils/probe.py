import os

from django.conf import settings
from jinja2 import Template

from apps.syslog.constants import DEFAULT_BK_SUPPLIER_ID, DEFAULT_JOB_BIZ, GSE_NAMESPACE, GSE_PROC_NAME, JOB_TIMEOUT
from blueking.component.shortcuts import get_client_by_user
from common.bk_api_utils.job import BkApiJobUtils


def read_file(path):
    with open(path, "r", encoding="utf-8") as file:
        content = file.read()
    return content


def write_file(path, content, newline="\n"):
    mkdir = path.replace("/sidecar.conf", "")
    if not os.path.exists(mkdir):
        os.makedirs(mkdir)
    with open(path, "w", newline=newline, encoding="utf-8") as file:
        file.write(content)


def render_content(content_template: str, params: dict):
    template = Template(content_template)
    content_result = template.render(**params)
    return content_result


meta = {"namespace": GSE_NAMESPACE, "name": GSE_PROC_NAME, "labels": {"proc_name": GSE_PROC_NAME}}


class ProcessManage(object):
    def __init__(self):
        self.client = get_client_by_user("admin")

    def register_proc_info(self, **kwargs):
        for host_info in kwargs["hosts"]:
            host_info.update(bk_supplier_id=DEFAULT_BK_SUPPLIER_ID)
        proc_info = {
            "meta": meta,
            "hosts": kwargs["hosts"],
            "spec": {
                "identity": {
                    "proc_name": GSE_PROC_NAME,
                    "setup_path": f"{kwargs['setup_path']}",
                    "pid_path": f"{kwargs['setup_path']}sidecar.pid",
                    "user": kwargs["user"],
                },
                "control": kwargs["control"],
                "resource": kwargs["resource"],
                "monitor_policy": {
                    "auto_type": 1,
                    "start_check_secs": 5,
                    "stop_check_secs": 5,
                    "start_retries": 3,
                    "start_interval": 20,
                    "crotab_rule": "",
                },
            },
        }
        resp = self.client.gse.register_proc_info(proc_info)
        if not resp["result"]:
            raise Exception(f'注册进程失败, {resp["message"]}')
        return resp["data"]

    def operate_proc(self, kwargs):
        for host_info in kwargs["hosts"]:
            host_info.update(bk_supplier_id=DEFAULT_BK_SUPPLIER_ID)
        operate_data = {
            "meta": meta,
            "op_type": kwargs["op_type"],
            "hosts": kwargs["hosts"],
        }
        resp = self.client.gse.operate_proc(operate_data)
        if not resp["result"]:
            raise Exception(resp["message"])
        return resp["data"]

    def get_proc_operate_result(self, task_id):
        resp = self.client.gse.get_proc_operate_result(task_id=task_id)
        if not resp["result"]:
            raise Exception(f'查询进程操作执行结果失败, {resp["message"]}')
        return resp["data"]

    def get_proc_status(self, kwargs):
        for host_info in kwargs["hosts"]:
            host_info.update(bk_supplier_id=DEFAULT_BK_SUPPLIER_ID)
        operate_data = {
            "meta": meta,
            "hosts": kwargs["hosts"],
        }
        resp = self.client.gse.get_proc_status(operate_data)
        if not resp["result"]:
            raise Exception(f'查询进程状态失败, {resp["message"]}')
        return resp["data"]

    def unregister_proc_info(self, kwargs):
        for host_info in kwargs["hosts"]:
            host_info.update(bk_supplier_id=DEFAULT_BK_SUPPLIER_ID)
        operate_data = {
            "meta": meta,
            "hosts": kwargs["hosts"],
        }
        resp = self.client.gse.unregister_proc_info(operate_data)
        if not resp["result"]:
            raise Exception(f'注销进程失败, {resp["message"]}')
        return resp["data"]


class JobManage(object):
    def __init__(self):
        self.client = get_client_by_user("admin")

    def distribute_files(self, kwargs):
        data = {
            "bk_biz_id": kwargs["bk_biz_id"] if "bk_biz_id" in kwargs else DEFAULT_JOB_BIZ,
            "file_target_path": kwargs["file_target_path"],
            "file_source_list": [
                {
                    "file_list": kwargs["file_list"],
                    "account": {"alias": "root"},
                    "server": {"ip_list": [{"bk_cloud_id": settings.SOURCE_BK_CLOUD_ID, "ip": settings.SOURCE_IP}]},
                }
            ],
            "target_server": {"ip_list": kwargs["ip_list"]},
            "account_alias": kwargs["account_alias"],
            "callback_url": kwargs["callback_url"],
        }
        resp = self.client.job.fast_transfer_file(data)
        if not resp["result"]:
            raise Exception(f'分发文件失败, {resp["message"]}')
        return resp["data"]

    def exe_script(self, kwargs):
        resp = BkApiJobUtils.fast_execute_script_v3(
            kwargs["bk_biz_id"] if "bk_biz_id" in kwargs else DEFAULT_JOB_BIZ,
            kwargs["script_type"],
            kwargs["script_content"],
            kwargs["script_param"] if "script_param" in kwargs else "",
            kwargs["ip_list"],
            kwargs["callback_url"],
            kwargs["timeout"] if "timeout" in kwargs else JOB_TIMEOUT,
            kwargs["account_alias"],
        )
        return resp
