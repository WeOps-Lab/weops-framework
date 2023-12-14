import base64

from blueking.component.shortcuts import get_client_by_user
from utils.app_log import logger
from utils.constants import OPERATION_CODE_STOP_JOB
from utils.exceptions import GetDateError, JobExeError


class BkApiJobUtils(object):
    """蓝鲸作业平台接口管理"""

    @staticmethod
    def fast_execute_script(
        bk_biz_id: int,
        script_content: str,
        script_param: str,
        script_type: int,
        ip_list: list,
        callback_url: str,
        timeout: int,
        account: str = "root",
        is_param_sensitive: int = 1,
        user: str = "admin",
        task_name: str = "weops_health_advisor",
    ):
        """
        快速执行脚本
        bk_biz_id:业务ID
        account_alias:执行帐号别名,eg:"root"
        script_language:脚本语言：1 - shell, 2 - bat, 3 - perl, 4 - python, 5 - powershell。
                        当使用script_content传入自定义脚本的时候，需要指定script_language
        script_content:脚本内容
        script_param:脚本参数 aa bb cc
        ip_list: 格式：[
            {
                "ip": "192.168.163.189",  主机IP
                "bk_cloud_id": 0   云区域ID，默认为0
            }
        ]
         callback_url:回调函数 "https://paas.cwbk.com/check_job_call?s_id=151"
         is_param_sensitive：敏感参数将会在执行详情页面上隐藏, 0:不是，1:是（默认）
        """
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "account": account,
            "script_content": base64.b64encode(script_content.encode("utf-8")).decode("utf-8"),
            "script_param": base64.b64encode(script_param.encode("utf-8")).decode("utf-8"),
            "script_type": script_type,
            "target_server": {"ip_list": ip_list},
            "is_param_sensitive": is_param_sensitive,
            "bk_callback_url": callback_url,
            "script_timeout": timeout,
            "task_name": task_name,
        }
        res = client.job.fast_execute_script(kwargs)
        if not res["result"]:
            logger.exception("作业平台V2-快速执行脚本-fast_execute_script-error: {}".format(res.get("message", str(res))))
            raise JobExeError("执行脚本出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def fast_transfer_file(
        bk_biz_id: int,
        file_target_path: str,
        file_source_list: list,
        ip_list: list,
        callback_url: str = "",
        transfer_mode: int = 2,
        timeout: int = 3600,
        account_id: str = "root",
        user: str = "admin",
    ):
        """
        快速分发文件V3
        """
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "account_id": account_id,
            "transfer_mode": transfer_mode,
            "file_target_path": file_target_path,
            "file_source": file_source_list,
            "target_server": {"ip_list": ip_list},
            "timeout": timeout,
        }
        if callback_url:
            kwargs["bk_callback_url"] = callback_url

        res = client.job.fast_transfer_file(kwargs)
        if not res["result"]:
            logger.exception("作业平台V3-快速分发文件-fast_transfer_file-error: {}".format(res.get("message", str(res))))
            raise JobExeError("分发文件出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def fast_push_file(
        bk_biz_id: int,
        file_target_path: str,
        file_source_list: list,
        ip_list: list,
        callback_url: str = "",
        timeout: int = 3600,
        account: str = "root",
        user: str = "admin",
    ):
        """快速分发文件"""
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "account": account,
            "file_target_path": file_target_path,
            "file_source": file_source_list,
            "target_server": {"ip_list": ip_list},
            "timeout": timeout,
        }
        if callback_url:
            kwargs["bk_callback_url"] = callback_url

        res = client.job.fast_push_file(kwargs)
        if not res["result"]:
            logger.exception("作业平台V2-快速分发文件-fast_push_file-error: {}".format(res.get("message", str(res))))
            raise JobExeError("分发文件出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def fast_execute_sql(
        bk_biz_id: int,
        script_content: str,
        db_account_id: int,
        ip_list: list,
        callback_url: str,
        timeout: int,
        user: str = "admin",
    ):
        """快速执行SQL脚本"""
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "db_account_id": db_account_id,
            "script_content": base64.b64encode(script_content.encode("utf-8")).decode("utf-8"),
            "target_server": {"ip_list": ip_list},
            "bk_callback_url": callback_url,
            "script_timeout": timeout,
        }
        res = client.job.fast_execute_sql(kwargs)
        if not res["result"]:
            logger.exception("作业平台V2-快速执行脚本-fast_execute_sql-error: {}".format(res.get("message", str(res))))
            raise JobExeError("执行脚本出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def get_job_instance_status(bk_biz_id: int, job_instance_id: int, user: str = "admin"):
        """获取作业实例状态"""
        client = get_client_by_user(user)
        kwargs = {"bk_biz_id": bk_biz_id, "job_instance_id": job_instance_id}
        res = client.job.get_job_instance_status(kwargs)
        if not res["result"]:
            logger.exception("作业平台V2-获取作业实例状态-get_job_instance_status-error: {}".format(res.get("message", str(res))))
            raise GetDateError("查询作业实例状态出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def get_job_instance_log(bk_biz_id: int, job_instance_id: int, user: str = "admin"):
        """根据ip查询作业执行日志"""
        client = get_client_by_user(user)
        kwargs = {"bk_biz_id": bk_biz_id, "job_instance_id": job_instance_id}
        res = client.job.get_job_instance_log(kwargs)
        if not res["result"]:
            logger.exception("作业平台V2-根据ip查询作业执行日志-get_job_instance_log-error: {}".format(res.get("message", str(res))))
            raise GetDateError("根据ip查询作业执行日志出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def fast_execute_script_v3(
        bk_biz_id: int,
        script_language: int,
        script_content: str,
        script_param: str,
        ip_list: list,
        callback_url: str,
        timeout: int = 7200,
        account_id: str = "root",
        is_param_sensitive: int = 1,
        user: str = "admin",
        task_name: str = "",
    ):
        """
        快速执行脚本 V3版本
        bk_biz_id:业务ID
        account_alias:执行帐号别名,eg:"root"
        script_language:脚本语言：1 - shell, 2 - bat, 3 - perl, 4 - python, 5 - powershell。
                        当使用script_content传入自定义脚本的时候，需要指定script_language
        script_content:脚本内容
        script_param:脚本参数 aa bb cc
        ip_list: 格式：[
            {
                "ip": "192.168.163.189",  主机IP
                "bk_cloud_id": 0   云区域ID，默认为0
            }
        ]
         callback_url:回调函数 "https://paas.cwbk.com/check_job_call?s_id=151"
         is_param_sensitive：敏感参数将会在执行详情页面上隐藏, 0:不是，1:是（默认）
        """
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "account_alias": account_id,
            "script_language": script_language,
            "script_content": base64.b64encode(script_content.encode("utf-8")).decode("utf-8"),
            "target_server": {"ip_list": ip_list},
            "is_param_sensitive": is_param_sensitive,
            "callback_url": callback_url,
            "timeout": timeout,
        }
        if script_param:
            kwargs["script_param"] = base64.b64encode(script_param.encode("utf-8")).decode("utf-8")

        if task_name:
            kwargs["task_name"] = task_name

        res = client.job.fast_execute_script_v3(kwargs)
        if not res["result"]:
            logger.exception("作业平台V3-快速执行脚本-fast_execute_script-error: {}".format(res.get("message", str(res))))
            raise JobExeError("执行脚本出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def get_job_instance_ip_log(
        bk_biz_id: int, job_instance_id: int, step_instance_id: int, bk_cloud_id: int, ip: str, user: str = "admin"
    ):
        """根据ip查询作业执行日志 V3版本"""
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "job_instance_id": job_instance_id,
            "step_instance_id": step_instance_id,
            "bk_cloud_id": bk_cloud_id,
            "ip": ip,
        }
        res = client.job.get_job_instance_ip_log_v3(kwargs)
        if not res["result"]:
            logger.exception(
                "作业平台V3-接口根据ip查询作业执行日志-get_job_instance_ip_log-error: {}".format(res.get("message", str(res)))
            )
            raise GetDateError("根据ip查询作业执行日志出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def get_batch_job_instance_ip_log_v3(
        bk_biz_id: int, job_instance_id: int, step_instance_id: int, ip_list: list, user: str = "admin"
    ):

        """根据ip列表查询作业执行日志 V3版本"""
        client = get_client_by_user(user)
        kwargs = {
            "bk_biz_id": bk_biz_id,
            "job_instance_id": job_instance_id,
            "step_instance_id": step_instance_id,
            "ip_list": ip_list,
        }
        res = client.job.batch_get_job_instance_ip_log_v3(kwargs)
        if not res["result"]:
            logger.exception(
                "作业平台V3-根据ip列表批量查询作业执行日志-batch_get_job_instance_ip_log-error: {}".format(res.get("message", str(res)))
            )
            raise GetDateError("根据ip列表批量查询作业执行日志出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def get_job_instance_status_v3(
        bk_biz_id: int, job_instance_id: int, return_ip_result: bool = False, user: str = "admin"
    ):

        """根据作业实例 ID 查询作业执行状态 V3版本"""
        client = get_client_by_user(user)
        kwargs = {"bk_biz_id": bk_biz_id, "job_instance_id": job_instance_id, "return_ip_result": return_ip_result}
        res = client.job.get_job_instance_status_v3(kwargs)
        if not res["result"]:
            logger.exception(
                "作业平台V3-根据作业实例ID查询作业执行状态-get_job_instance_status-error: {}".format(res.get("message", str(res)))
            )
            raise GetDateError("根据作业实例ID查询作业执行状态出错: {}".format(res.get("message", str(res))))
        return res["data"]

    @staticmethod
    def operate_job_instance_v3(bk_biz_id: int, job_instance_id: int, user: str = "admin"):

        """根据job_id, bk_biz_id，停止作业 V3版本"""
        client = get_client_by_user(user)
        kwargs = {"bk_biz_id": bk_biz_id, "job_instance_id": job_instance_id, "operation_code": OPERATION_CODE_STOP_JOB}
        res = client.job.operate_job_instance(kwargs)
        if not res["result"]:
            logger.exception("作业平台V3-作业实例操作-operate_job_instance-error: {}".format(res.get("message", str(res))))
            raise JobExeError("作业实例操作出错: {}".format(res.get("message", str(res))))
        return res["data"]
