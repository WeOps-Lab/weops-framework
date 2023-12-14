from datetime import datetime, timedelta

from django.conf import settings
from django.db import transaction

from apps.syslog.constants import (
    COLLECTOR,
    CONTROL_MAP,
    DEFAULT_JOB_BIZ,
    GRAYLOG_API_TOKEN,
    GRAYLOG_URL,
    GSE_ACTION,
    GSE_USER_MAP,
    JOB_DEFAULT_CODE,
    JOB_SUCCESS_CODE,
    L_INSTALL_DOWNLOAD_URL,
    L_SIDECAR_DOWNLOAD_URL,
    OS_TYPE_USER,
    PAGE_INFO,
    PROBE_FILE_DICT,
    PROBE_NAME_DICT,
    PROBE_TYPES,
    RESOURCE,
    SIDECAR_FILE_DICT,
    SYSLOG_CALLBACK_URL,
    TARGET_PATH_DICT,
    UNINSTALL_SCRIPT_DICT,
    W_SIDECAR_DOWNLOAD_URL,
)
from apps.syslog.models import Node, ProbeJob
from apps.syslog.utils.api import graylog_api
from apps.syslog.utils.probe import JobManage, ProcessManage, read_file, render_content, write_file
from blueapps.core.exceptions import BlueException, ServerBlueException
from blueking.component.shortcuts import get_client_by_user
from common.bk_api_utils.cc import BkApiCCUtils
from common.bk_api_utils.job import BkApiJobUtils
from utils.app_log import logger


class ProbeService(object):
    @staticmethod
    def probe_list():
        """查探针列表"""
        resp = graylog_api.get_probe(params=PAGE_INFO)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        items = []
        for collector in resp["data"].get("collectors", []):
            items.append(
                dict(
                    id=collector["id"],
                    name=collector["name"],
                    os_type=collector["node_operating_system"],
                )
            )
        return items

    @staticmethod
    def config_list():
        """查询配置"""
        resp = graylog_api.get_configs(params=PAGE_INFO)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return resp["data"].get("configurations", [])

    @staticmethod
    def action_graylog_probe(kwargs):
        """操作graylog的探针"""
        resp = graylog_api.action(json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"操作失败，详情：{msg}")

    @staticmethod
    def host_list(kwargs):
        """主机列表查询"""
        client = get_client_by_user("admin")
        resp = client.nodeman.search_host(kwargs)
        if not resp["result"]:
            raise Exception(resp["message"])
        exist_host = [
            i.bk_host_id
            for i in Node.objects.filter(bk_host_id__in=[i["bk_host_id"] for i in resp["data"].get("list", [])])
        ]
        resp["data"].update(exist_host=exist_host)
        return resp["data"]

    @staticmethod
    def search_sidecar_map(node_name_set):
        """查sidecar信息"""
        resp = graylog_api.get_sidecars(json=PAGE_INFO)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return {i["node_name"]: i for i in resp["data"].get("sidecars", []) if i["node_name"] in node_name_set}

    @staticmethod
    def search_host_map(bk_host_ids, conditions, page=1, page_size=200):
        """查主机信息"""
        query_data = {
            "page": page,
            "pagesize": page_size,
            "bk_host_id": bk_host_ids,
            "conditions": [],
        }
        for condition in conditions:
            if condition["key"] == "bk_biz_id":
                query_data.update(bk_biz_id=condition["value"])
                continue
            if condition["key"] == "bk_host_id":
                query_data.update(bk_host_id=condition["value"])
                continue
            query_data["conditions"].append(condition)
        data = ProbeService.host_list(query_data)
        return {i["bk_host_id"]: i for i in data.get("list", [])}, data.get("total", 0)

    @staticmethod
    def supplement_sidecar_status(items):
        """
        补充sidecar节点状态
        status为sidecar状态：
            "1" 安装中
            "2" 安装失败
            "3" 正常(优先级最高)
            "4" 异常
            "5" 停止
            "6" 卸载中
            "7" 卸载失败
        """

        sidecar_jobs = ProbeJob.objects.filter(probe_type=COLLECTOR, node_id__in=[i["id"] for i in items])

        install_sidecar_map, unload_sidecar_map = {}, {}
        for sidecar_job in sidecar_jobs:
            if sidecar_job.action == "install":
                if sidecar_job.job_code == JOB_DEFAULT_CODE:
                    status = "1"
                elif sidecar_job.job_code == JOB_SUCCESS_CODE:
                    status = "5"
                else:
                    status = "2"
                install_sidecar_map[sidecar_job.node_id] = status
            else:
                if sidecar_job.job_code == JOB_DEFAULT_CODE:
                    status = "6"
                elif sidecar_job.job_code == JOB_SUCCESS_CODE:
                    status = "0"
                else:
                    status = "7"
                unload_sidecar_map[sidecar_job.node_id] = status

        for item in items:

            # 安装状态
            if item["id"] in install_sidecar_map:
                item.update(sidecar_status=install_sidecar_map[item["id"]])

            # 运行状态
            if "active" in item:
                if item["active"]:
                    item["sidecar_status"] = "3"
                else:
                    item["sidecar_status"] = "4"

            # 卸载状态
            if item["id"] in unload_sidecar_map:
                item.update(sidecar_status=unload_sidecar_map[item["id"]])

    @staticmethod
    def supplement_probe_status(items):
        """
        补充探针状态
        status为探针状态：
            "1" 未安装
            "2" 安装中
            "3" 安装失败
            "4" 未启动
            "5" 启动中
            "6" 正常
            "7" 异常
            "8" 卸载中
            "9" 卸载失败
        """
        config_list = ProbeService.config_list()
        config_map = {i["id"]: i["name"] for i in config_list}
        collector_list = ProbeService.probe_list()
        collector_map = {i["id"]: i["name"] for i in collector_list}
        probe_jobs = ProbeJob.objects.filter(node_id__in=[i["id"] for i in items], probe_type__in=PROBE_TYPES)

        # 构造安装与卸载状态map
        install_probe_map, unload_probe_map = {}, {}
        for probe_job in probe_jobs:
            if probe_job.action == "install":
                if probe_job.node_id not in install_probe_map:
                    install_probe_map[probe_job.node_id] = {}
                if probe_job.job_code == JOB_DEFAULT_CODE:
                    status = "2"
                elif probe_job.job_code == JOB_SUCCESS_CODE:
                    status = "4"
                else:
                    status = "3"
                install_probe_map[probe_job.node_id][probe_job.probe_type] = status
            else:
                if probe_job.node_id not in unload_probe_map:
                    unload_probe_map[probe_job.node_id] = {}
                if probe_job.job_code == JOB_DEFAULT_CODE:
                    status = "8"
                elif probe_job.job_code == JOB_SUCCESS_CODE:
                    status = "1"
                else:
                    status = "9"
                unload_probe_map[probe_job.node_id][probe_job.probe_type] = status

        for item in items:

            # 构造graylog中探针状态map（每个节点都需单独构造）
            probe_status_map = {}
            if item.get("node_details", {}).get("status"):
                for collector_info in item["node_details"]["status"].get("collectors", []):
                    status = "0"
                    if collector_info["status"] == 0:
                        status = "6"
                    elif collector_info["status"] == 2:
                        status = "7"
                    elif collector_info["status"] == 3:
                        status = "4"
                    probe_status_map[collector_info["collector_id"]] = status

            # 构造探针与配置文件的关联map（collector_id为graylog中探针ID，configuration_id为graylog中探针配置文件ID）
            collector_config_map = {i["collector_id"]: i["configuration_id"] for i in item.get("assignments", [])}

            probe_list = []
            for collector_id in item.get("collectors", []):
                probe_info = dict(
                    config_id=collector_config_map.get(collector_id, ""),
                    probe_id=collector_id,
                    probe_config=config_map.get(collector_config_map.get(collector_id, ""), ""),
                    probe_type=collector_map.get(collector_id, ""),
                    probe_status="1",
                )

                # 安装状态
                if item["id"] in install_probe_map and probe_info["probe_type"] in install_probe_map[item["id"]]:
                    probe_info.update(probe_status=install_probe_map[item["id"]][probe_info["probe_type"]])

                # graylog上的运行状态
                if collector_id in probe_status_map:
                    probe_info.update(probe_status=probe_status_map[collector_id])

                # 卸载状态
                if item["id"] in unload_probe_map and probe_info["probe_type"] in unload_probe_map[item["id"]]:
                    probe_info.update(probe_status=unload_probe_map[item["id"]][probe_info["probe_type"]])

                probe_list.append(probe_info)
            item.update(probes=probe_list)

    @staticmethod
    def sidecar_list(kwargs):
        """查询sidecar节点列表，含主机信息、sidecar信息、探针信息"""
        order = kwargs.get("order", "id")
        reverse = kwargs.get("reverse", False)
        conditions = kwargs.get("conditions", [])
        page, page_size = int(kwargs.get("page", 1)), int(kwargs.get("page_size", 10))
        count, items = 0, []
        if conditions:
            # 有查询条件以节点管理接口为主，其他数据源作为补充数据
            node_objs = Node.objects.all()
            node_map = {i.bk_host_id: i for i in node_objs}
            host_map, count = ProbeService.search_host_map(list(node_map.keys()), conditions, page, page_size)
            sidecar_map = ProbeService.search_sidecar_map(
                {node_map[bk_host_id].node_name for bk_host_id in host_map.keys()}
            )

            for bk_host_id, host_info in host_map.items():
                node_obj = node_map[bk_host_id]
                host_info.update(
                    id=node_obj.id,
                    is_manual=node_obj.is_manual,
                    **sidecar_map.get(node_obj.node_name, {}),
                )
                items.append(host_info)
        else:
            # 无查询条件以表数据为主，其他数据源作为补充数据
            query_set = Node.objects.filter()
            count = query_set.count()
            start, end = (page - 1) * page_size, page * page_size
            nodes = query_set[start:end]
            sidecar_map = ProbeService.search_sidecar_map({i.node_name for i in nodes})
            host_map, _ = ProbeService.search_host_map([i.bk_host_id for i in nodes], conditions)

            for node in nodes:
                item = dict(
                    **host_map.get(node.bk_host_id, {}),
                    **sidecar_map.get(node.node_name, {}),
                )
                item.update(id=node.id, is_manual=node.is_manual)
                items.append(item)

        # 补充控制器状态
        ProbeService.supplement_sidecar_status(items)
        # 补充探针状态
        ProbeService.supplement_probe_status(items)
        # 排序
        items.sort(key=lambda x: x[order], reverse=reverse)
        return dict(total=count, list=items)

    @staticmethod
    def get_host_path(root_path, host):
        """获取主机的配置文件地址"""
        if host["os_type"] == "linux":
            path = "{}/sidecar/linux/etc/{}/sidecar.conf".format(root_path, f'{host["ip"]}-{host["bk_cloud_id"]}')
        elif host["os_type"] == "windows":
            path = "{}/sidecar/windows/etc/{}/sidecar.conf".format(root_path, f'{host["ip"]}-{host["bk_cloud_id"]}')
        else:
            raise Exception(f"操作系统{host['os_type']}, 不支持！")
        return path

    @staticmethod
    def bulk_generate_sidecar_node_conf(nodes):
        """批量生成sidecar节点配置文件"""
        windows_template = read_file(
            "{}/sidecar/windows/etc/sidecar.conf".format(settings.CURRENT_FILE_PATH.rstrip("/"))
        )
        windows_template = windows_template.replace("\n", "\r\n")
        linux_template = read_file("{}/sidecar/linux/etc/sidecar.conf".format(settings.CURRENT_FILE_PATH.rstrip("/")))
        for node in nodes:
            params = dict(
                GRAYLOG_SERVER_URL=f"{GRAYLOG_URL}/api/",
                GRAYLOG_API_TOKEN=GRAYLOG_API_TOKEN,
                CMDB_HOST_IP=f'{node["ip"]}-{node["bk_cloud_id"]}',
            )
            path = ProbeService.get_host_path(settings.CURRENT_FILE_PATH.rstrip("/"), node)
            template = linux_template if node["os_type"] == "linux" else windows_template
            content = render_content(template, params=params)
            newline = "\n" if node["os_type"] == "linux" else "\r\n"
            write_file(path, content, newline=newline)

    @staticmethod
    def check_host(hosts):
        """检查已经存在的主机节点"""
        host_map = {i["bk_host_id"]: i["ip"] for i in hosts}
        objs = Node.objects.filter(bk_host_id__in=list(host_map.keys()))
        if objs:
            return {i.bk_host_id: host_map[i.bk_host_id] for i in objs}

    @staticmethod
    def create_sidecar(username, kwargs):
        """自动创建sidecar节点"""
        node_list = [
            Node(
                node_name=f'{host["ip"]}-{host["bk_cloud_id"]}',
                bk_host_id=host["bk_host_id"],
                created_by=username,
                updated_by=username,
            )
            for host in kwargs["hosts"]
        ]
        Node.objects.bulk_create(node_list, batch_size=100)

        # 注册gse进程
        ProbeService.register_proc(kwargs)

        # 批量生成sidecar节点配置
        ProbeService.bulk_generate_sidecar_node_conf(kwargs["hosts"])

        # 作业平台下发sidecar，待下发作业完成回调启动gse进程
        node_map = dict(
            Node.objects.filter(bk_host_id__in=[i["bk_host_id"] for i in kwargs["hosts"]]).values_list(
                "bk_host_id", "id"
            )
        )
        job_list = []
        for host in kwargs["hosts"]:
            job_data = dict(ip_list=[dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"])], os_type=host["os_type"])
            job_instance_id = ProbeService.distribute_sidecar(job_data)
            job_list.append(
                ProbeJob(
                    probe_type=COLLECTOR,
                    action="install",
                    job_id=job_instance_id,
                    node_id=node_map[host["bk_host_id"]],
                )
            )
        ProbeJob.objects.bulk_create(job_list, batch_size=100)

    @staticmethod
    def create_sidecar_by_manual(username, kwargs):
        """手动创建sidecar节点"""
        node_list = [
            Node(
                node_name=f'{host["ip"]}-{host["bk_cloud_id"]}',
                bk_host_id=host["bk_host_id"],
                is_manual=True,
                created_by=username,
                updated_by=username,
            )
            for host in kwargs["hosts"]
        ]
        Node.objects.bulk_create(node_list, batch_size=100)

        node_map = dict(
            Node.objects.filter(bk_host_id__in=[i["bk_host_id"] for i in kwargs["hosts"]]).values_list(
                "bk_host_id", "id"
            )
        )

        job_list = []
        for host in kwargs["hosts"]:
            # 构造sidecar安装记录
            job_list.append(
                ProbeJob(
                    probe_type=COLLECTOR,
                    action="install",
                    job_code=JOB_SUCCESS_CODE,
                    node_id=node_map[host["bk_host_id"]],
                )
            )

            # 构造探针安装记录
            for probe in PROBE_NAME_DICT.get(host["os_type"], {}).keys():
                job_list.append(
                    ProbeJob(
                        probe_type=probe,
                        action="install",
                        job_code=JOB_SUCCESS_CODE,
                        node_id=node_map[host["bk_host_id"]],
                    )
                )
        ProbeJob.objects.bulk_create(job_list, batch_size=100)

    @staticmethod
    @transaction.atomic
    def unload_sidecar_by_manual(kwargs):
        """手动卸载sidecar节点"""
        ProbeJob.objects.filter(node_id__in=[host["id"] for host in kwargs["hosts"]]).delete()
        Node.objects.filter(id__in=[host["id"] for host in kwargs["hosts"]]).delete()

    @staticmethod
    def distribute_sidecar(kwargs):
        """下发sidecar程序文件"""
        kwargs.update(
            file_target_path=TARGET_PATH_DICT[kwargs["os_type"]],
            file_list=[],
            account_alias=OS_TYPE_USER[kwargs["os_type"]],
            callback_url=SYSLOG_CALLBACK_URL,
        )
        kwargs["file_list"].extend(SIDECAR_FILE_DICT[kwargs["os_type"]])
        host_info = kwargs["ip_list"][0]
        host_info.update(os_type=kwargs["os_type"])
        config_path = ProbeService.get_host_path(settings.FILE_PATH.rstrip("/"), host_info)
        kwargs["file_list"].append(config_path)
        job_result = JobManage().distribute_files(kwargs)
        return job_result["job_instance_id"]

    @staticmethod
    def distribute_probe(kwargs):
        """下发探针程序文件"""
        bin_path = "bin/" if kwargs["os_type"] == "linux" else "bin\\"
        file_target_path = TARGET_PATH_DICT[kwargs["os_type"]] + bin_path
        kwargs.update(
            file_target_path=file_target_path,
            file_list=[PROBE_FILE_DICT[kwargs["os_type"]][kwargs["probe_type"]]],
            account_alias=OS_TYPE_USER[kwargs["os_type"]],
            callback_url=SYSLOG_CALLBACK_URL,
        )
        job_result = JobManage().distribute_files(kwargs)
        return job_result["job_instance_id"]

    @staticmethod
    def register_proc(kwargs):
        """注册gse进程"""
        linux_data = dict(setup_path=TARGET_PATH_DICT["linux"], hosts=[])
        windows_data = dict(setup_path=TARGET_PATH_DICT["windows"], hosts=[])
        for host in kwargs["hosts"]:
            if host["os_type"] == "linux":
                linux_data["hosts"].append(dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"]))
            elif host["os_type"] == "windows":
                windows_data["hosts"].append(dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"]))
        if linux_data["hosts"]:
            ProcessManage().register_proc_info(
                resource=RESOURCE,
                user=GSE_USER_MAP["linux"],
                control=CONTROL_MAP["linux"],
                **linux_data,
            )
        if windows_data["hosts"]:
            ProcessManage().register_proc_info(
                resource=RESOURCE,
                user=GSE_USER_MAP["windows"],
                control=CONTROL_MAP["windows"],
                **windows_data,
            )

    @staticmethod
    def unregister_proc_info(kwargs):
        """注销gse进程"""
        return ProcessManage().unregister_proc_info(kwargs)

    @staticmethod
    def action_sidecar(kwargs):
        """操作sidecar"""
        if kwargs["action"] == "unload":
            if kwargs.get("is_manual"):
                # 手动卸载，删除主机节点
                ProbeService.unload_sidecar_by_manual(kwargs)
            else:
                # 卸载操作，默认会先执行stop操作
                ProbeService.action_gse(dict(op_type=GSE_ACTION["stop"], hosts=kwargs["hosts"]))
                ProbeService.unload_sidecar(kwargs)
        else:
            # 进程操作
            op_type = GSE_ACTION[kwargs["action"]]
            task_id = ProbeService.action_gse(dict(op_type=op_type, hosts=kwargs["hosts"]))
            return task_id

    @staticmethod
    def install_probe(kwargs):
        """安装探针"""
        job_list = []
        for host in kwargs["hosts"]:
            job_data = dict(ip_list=[dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"])], os_type=host["os_type"])
            for probe in kwargs["probes"]:
                probe_type = probe["probe_type"]
                job_data.update(probe_type=probe_type)
                job_instance_id = ProbeService.distribute_probe(job_data)
                job_list.append(
                    ProbeJob(
                        probe_type=probe_type,
                        action="install",
                        job_id=job_instance_id,
                        node_id=host["id"],
                    )
                )
        ProbeJob.objects.bulk_create(job_list, batch_size=100)

    @staticmethod
    def unload_probe(kwargs):
        """卸载探针"""
        job_list = []
        for host in kwargs["hosts"]:
            os_type = host["os_type"]
            for probe in kwargs["probes"]:
                probe_type = probe["probe_type"]
                job_dict = UNINSTALL_SCRIPT_DICT[os_type]
                bin_path = "bin/" if os_type == "linux" else "bin\\"
                source_path = f"{TARGET_PATH_DICT[os_type]}{bin_path}{PROBE_NAME_DICT[os_type][probe_type]}"
                job_dict.update(
                    ip_list=[dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"])],
                    callback_url=SYSLOG_CALLBACK_URL,
                    account_alias=OS_TYPE_USER[os_type],
                    script_content=job_dict["script_content"].format(source_path),
                )
                result = JobManage().exe_script(job_dict)
                job_list.append(
                    ProbeJob(
                        probe_type=probe_type,
                        action="unload",
                        job_id=result["job_instance_id"],
                        node_id=host["id"],
                    )
                )
        ProbeJob.objects.bulk_create(job_list, batch_size=100)

    @staticmethod
    def action_probe(kwargs):
        """操作探针"""
        if kwargs["action"] == "install":
            # 下发探针文件
            ProbeService.install_probe(kwargs)
        elif kwargs["action"] == "unload":
            # 卸载探针
            ProbeService.unload_probe(kwargs)
        else:
            # graylog探针操作
            collector_ids = [i["id"] for i in kwargs["probes"]]
            data = {
                "action": kwargs["action"],
                "collectors": [
                    dict(sidecar_id=host["sidecar_id"], collector_ids=collector_ids) for host in kwargs["hosts"]
                ],
            }
            ProbeService.action_graylog_probe(data)

    @staticmethod
    def get_collector_ids(probe_type):
        """查询某个类型的探针对应的collector_ids"""
        resp = graylog_api.get_probe(params=dict(query=probe_type, **PAGE_INFO))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        return {collector["id"] for collector in resp["data"].get("collectors", [])}

    @staticmethod
    def get_node_assignments(node_name):
        """node_id与node_name同名，解决不能通过ID查询问题"""
        resp = graylog_api.get_sidecars(json=dict(query=node_name, **PAGE_INFO))
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"查询失败，详情：{msg}")
        node_assignments = []
        for sidecar in resp["data"].get("sidecars", []):
            if sidecar["node_id"] == node_name:
                node_assignments = sidecar["assignments"]
        return node_assignments

    @staticmethod
    def clear_config_by_node_collector(node_name, probe_type):
        """清除探针配置文件"""
        collector_ids = ProbeService.get_collector_ids(probe_type)
        node_assignments = ProbeService.get_node_assignments(node_name)
        assignments = [i for i in node_assignments if i["collector_id"] not in collector_ids]
        clear_data = {"nodes": [{"node_id": node_name, "assignments": assignments}]}
        ProbeService.action_probe_configs(clear_data)

    @staticmethod
    def clear_config_by_node(node_name):
        """清除节点配置文件"""
        clear_data = {"nodes": [{"node_id": node_name, "assignments": []}]}
        ProbeService.action_probe_configs(clear_data)

    @staticmethod
    def action_probe_configs(kwargs):
        """操作节点探针配置"""
        resp = graylog_api.associative_configuration(json=kwargs)
        if not resp["result"]:
            msg = f"错误类型{resp.get('type')}，详情{resp.get('message')}"
            raise ServerBlueException(f"操作失败，详情：{msg}")

    @staticmethod
    def action_gse(kwargs):
        """操作GSE，sidecar的启动停止和重启操作"""
        result = ProcessManage().operate_proc(kwargs)
        return result["task_id"]

    @staticmethod
    def unload_sidecar(kwargs):
        """卸载sidecar"""
        job_list = []
        for host in kwargs["hosts"]:
            os_type = host["os_type"]
            job_dict = UNINSTALL_SCRIPT_DICT[os_type]
            job_dict.update(
                ip_list=[dict(bk_cloud_id=host["bk_cloud_id"], ip=host["ip"])],
                callback_url=SYSLOG_CALLBACK_URL,
                account_alias=OS_TYPE_USER[os_type],
                script_content=job_dict["script_content"].format(TARGET_PATH_DICT[os_type]),
            )
            result = JobManage().exe_script(job_dict)
            job_list.append(
                ProbeJob(
                    probe_type=COLLECTOR,
                    action="unload",
                    job_id=result["job_instance_id"],
                    node_id=host["id"],
                )
            )
        ProbeJob.objects.bulk_create(job_list, batch_size=100)

    @staticmethod
    def install_sidecar_call(obj):
        """安装探针后回调函数"""
        if obj.job_code != JOB_SUCCESS_CODE:
            return
        data = BkApiCCUtils.get_host_base_info(get_client_by_user("admin"), bk_host_id=obj.node.bk_host_id)
        host_dict = {i["bk_property_id"]: i["bk_property_value"] for i in data}
        action_data = dict(
            action="start", hosts=[dict(ip=host_dict["bk_host_innerip"], bk_cloud_id=host_dict["bk_cloud_id"])]
        )
        ProbeService.action_sidecar(action_data)

    @staticmethod
    def unload_sidecar_call(obj):
        """卸载探针后回调函数"""
        data = BkApiCCUtils.get_host_base_info(get_client_by_user("admin"), bk_host_id=obj.node.bk_host_id)
        host_dict = {i["bk_property_id"]: i["bk_property_value"] for i in data}
        action_data = dict(hosts=[dict(ip=host_dict["bk_host_innerip"], bk_cloud_id=host_dict["bk_cloud_id"])])
        ProbeService.unregister_proc_info(action_data)
        node_id, node_name = obj.node_id, obj.node.node_name
        ProbeJob.objects.filter(node_id=node_id).delete()
        Node.objects.filter(id=node_id).delete()
        ProbeService.clear_config_by_node(node_name)

    @staticmethod
    def callback(job_id, job_code):
        """作业回调函数"""
        obj = ProbeJob.objects.filter(job_id=job_id).first()
        if not obj:
            raise Exception(f"作业实例{job_id}，不存在！")
        obj.job_code = job_code
        obj.save()
        if obj.probe_type == COLLECTOR and obj.action == "install":
            ProbeService.install_sidecar_call(obj)
        elif obj.probe_type == COLLECTOR and obj.action == "unload":
            ProbeService.unload_sidecar_call(obj)
        elif obj.action == "install":
            ProbeJob.objects.filter(node_id=obj.node_id, probe_type=obj.probe_type, action="unload").delete()
        elif obj.action == "unload":
            node_name, probe_type = obj.node.node_name, obj.probe_type
            ProbeJob.objects.filter(node_id=obj.node_id, probe_type=probe_type).delete()
            ProbeService.clear_config_by_node_collector(node_name, probe_type)

    @staticmethod
    def check_not_callback_job(expire_time):
        """检查未回调的job"""
        before_datetime = datetime.now() - timedelta(seconds=expire_time)
        objs = ProbeJob.objects.filter(job_code=JOB_DEFAULT_CODE, created_at__lt=before_datetime)
        for obj in objs:
            resp = BkApiJobUtils.get_job_instance_status(DEFAULT_JOB_BIZ, obj.job_id)
            if not resp["is_finished"]:
                continue
            try:
                ProbeService.callback(obj.job_id, resp["job_instance"]["status"])
            except BlueException as e:
                logger.exception(f"syslog callback, error: {e.message}")
            except Exception as e:
                logger.exception(e)

    @staticmethod
    def get_installation_steps(data):
        """获取安装步骤"""
        ip, bk_cloud_id, os_type = data["ip"], data["bk_cloud_id"], data["os_type"].lower()
        if os_type == "linux":
            return ProbeService.linux_step(f"{ip}-{bk_cloud_id}", GRAYLOG_API_TOKEN, GRAYLOG_URL)
        elif os_type == "windows":
            return ProbeService.windows_step(f"{ip}-{bk_cloud_id}", GRAYLOG_API_TOKEN, GRAYLOG_URL)

    @staticmethod
    def windows_step(node_id, gl_token, gl_host):
        """windows安装步骤"""

        return [
            {
                "title": "下载安装包",
                "content": "下载安装包",
                "download_url": W_SIDECAR_DOWNLOAD_URL,
            },
            {
                "title": "创建以下目录",
                "content": "c:/gse",
            },
            {
                "title": "执行安装脚本，在指定目录下安装控制器和探针",
                "content": r'.\install_sidecar.bat "{}" "{}" "{}"'.format(node_id, gl_token, gl_host),
            },
        ]

    @staticmethod
    def linux_step(node_id, gl_token, gl_host):
        """linux安装步骤"""
        params = [L_INSTALL_DOWNLOAD_URL, node_id, gl_token, gl_host, L_SIDECAR_DOWNLOAD_URL]
        return [
            {
                "title": "下载安装包",
                "content": 'curl -sSL {}|bash -s - -n "{}" -t "{}" -s "{}" -d "{}"'.format(*params),
            },
        ]
