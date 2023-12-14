import os

from django.conf import settings

# 输出地址
LOG_OUTPUT_HOST = os.getenv("BKAPP_LOG_OUTPUT_HOST", "127.0.0.1:8000")

# graylog服务URL
GRAYLOG_URL = os.getenv("BKAPP_GRAYLOG_URL", "http://datainsight.weops.com")

# graylog服务auth
GRAYLOG_AUTH = os.getenv("BKAPP_GRAYLOG_AUTH", "YWRtaW46ZGF0YWluc2lnaHQteA==")

# kafka host
KAFKA_HOST = os.getenv("BKAPP_KAFKA_HOST", "10.10.25.156:9092")

# local_log kafka topic
LOCAL_LOG_TOPIC = os.getenv("BKAPP_LOCAL_LOG_KAFKA_TOPIC", "dashboard-e")

# local_log input data
LOCAL_INPUT = {
    "title": "local_log",
    "type": "org.graylog2.inputs.raw.kafka.RawKafkaInput",
    "configuration": {
        "throttling_allowed": False,
        "legacy_mode": False,
        "bootstrap_server": KAFKA_HOST,
        "zookeeper": "127.0.0.1:2181",
        "topic_filter": LOCAL_LOG_TOPIC,
        "fetch_min_bytes": 100,
        "fetch_wait_max": 100,
        "threads": 2,
        "offset_reset": "largest",
        "group_id": "datainsight",
        "custom_properties": "",
        "override_source": None,
    },
    "global": True,
}

# 告警推送rest api
ALARM_API = os.getenv(
    "BKAPP_ALARM_SEND_REST_API",
    "http://paas.weops.com/o/cw_uac_saas/alarm/collect/event/api/394bdc36-6c1a-4e8d-a323-1ab77e8af7cb/",
)

# 告警推送SECRET
ALARM_SECRET = os.getenv("BKAPP_ALARM_SEND_SECRET", "irQRbsm9Su3goP3H2EGFCSZZ5y5uHaQy")

APP_MODULE_NAME = "日志"

MONITOR = "告警策略"

SIDECAR = "日志控制器"

PROBE = "日志探针"

NOTICE_NAME = "蓝鲸告警通知-Weops"

NOTICE_TYPE = "bk_uac-notification-v1"

DEFAULT_JOB_BIZ = 9991001

# 本服务的WEB地址
WEB_URL = f"{settings.BK_PAAS_HOST}/{'o' if os.getenv('BK_ENV') == 'production' else 't'}/{settings.APP_ID}/"

# 文件下发回调地址
SYSLOG_CALLBACK_URL = WEB_URL + "syslog/job_call_back/"

# 作业平台任务默认未回调的状态码
JOB_DEFAULT_CODE = 0

# 作业平台成功状态码
JOB_SUCCESS_CODE = 3

# job默认超时时间
JOB_TIMEOUT = 3600

# gse的命名空间
GSE_NAMESPACE = "gse"
# gse的进程名称
GSE_PROC_NAME = "sidecar"
# gse的进程操作
GSE_ACTION = {
    "start": 0,
    "stop": 8,
    "restart": 7,
}
# 默认开发商id
DEFAULT_BK_SUPPLIER_ID = 0

# GRAYLOG_API_TOKEN
GRAYLOG_API_TOKEN = os.getenv("BKAPP_GRAYLOG_API_TOKEN", "1h2tefk0a87pvtg6ov6sbio77e80rh8o5tl1bed6nmvl9kotoihf")

# RESOURCE
RESOURCE = {
    "cpu": 20.0,
    "mem": 20.0,
}

OS_TYPE_USER = {
    "linux": "root",
    "windows": "system",
}

GSE_USER_MAP = {
    "linux": "root",
    "windows": "Administrator",
}

# 因stop和kill操作会有状态校验无法通过，故使用reload代替
CONTROL_MAP = {
    "linux": {
        "start_cmd": "./start.sh sidecar",
        "reload_cmd": "./stop.sh sidecar",
        "restart_cmd": "./restart.sh sidecar",
    },
    "windows": {
        "start_cmd": r".\start.bat sidecar",
        "reload_cmd": r".\stop.bat sidecar",
        "restart_cmd": r".\restart.bat sidecar",
    },
}

# 卸载命令
UNINSTALL_SCRIPT_DICT = {
    "linux": {
        "script_type": 1,
        "script_content": "rm -rf {}",
    },
    "windows": {
        "script_type": 5,
        "script_content": 'Remove-Item -Path "{}" -Recurse',
    },
}

# 文件下发的目录地址
TARGET_PATH_DICT = {
    "linux": "/usr/local/gse/sidecar/",
    "windows": "C:\\gse\\sidecar\\",
}

# 控制器源文件地址
SIDECAR_FILE_DICT = {
    "linux": [
        "{}/sidecar/linux/bin/sidecar".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/linux/bin/start.sh".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/linux/bin/stop.sh".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/linux/bin/restart.sh".format(settings.FILE_PATH.rstrip("/")),
    ],
    "windows": [
        "{}/sidecar/windows/bin/sidecar.exe".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/windows/bin/start.bat".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/windows/bin/stop.bat".format(settings.FILE_PATH.rstrip("/")),
        "{}/sidecar/windows/bin/restart.bat".format(settings.FILE_PATH.rstrip("/")),
    ],
}

# 控制器（作为一种特殊的探针类型）
COLLECTOR = "sidecar"
# 探针类型
AUDITBEAT = "auditbeat"
FILEBEAT = "filebeat"
PACKETBEAT = "packetbeat"
UNIPROBE = "uniprobe"
WINLOGBEAT = "winlogbeat"
METRICBEAT = "metricbeat"

# 探针类型列表
PROBE_TYPES = [AUDITBEAT, FILEBEAT, PACKETBEAT, UNIPROBE, WINLOGBEAT, METRICBEAT]

# 探针名称
PROBE_NAME_DICT = {
    "linux": {
        AUDITBEAT: "auditbeat",
        FILEBEAT: "filebeat",
        PACKETBEAT: "packetbeat",
        UNIPROBE: "uniprobe",
        METRICBEAT: "metricbeat",
    },
    "windows": {
        FILEBEAT: "filebeat.exe",
        WINLOGBEAT: "winlogbeat.exe",
        PACKETBEAT: "packetbeat.exe",
        METRICBEAT: "metricbeat.exe",
    },
}

# 探针源文件地址
PROBE_FILE_DICT = {
    "linux": {
        AUDITBEAT: "{}/sidecar/linux/bin/auditbeat".format(settings.FILE_PATH.rstrip("/")),
        FILEBEAT: "{}/sidecar/linux/bin/filebeat".format(settings.FILE_PATH.rstrip("/")),
        PACKETBEAT: "{}/sidecar/linux/bin/packetbeat".format(settings.FILE_PATH.rstrip("/")),
        UNIPROBE: "{}/sidecar/linux/bin/uniprobe".format(settings.FILE_PATH.rstrip("/")),
        METRICBEAT: "{}/sidecar/linux/bin/metricbeat".format(settings.FILE_PATH.rstrip("/")),
    },
    "windows": {
        FILEBEAT: "{}/sidecar/windows/bin/filebeat.exe".format(settings.FILE_PATH.rstrip("/")),
        WINLOGBEAT: "{}/sidecar/windows/bin/winlogbeat.exe".format(settings.FILE_PATH.rstrip("/")),
        PACKETBEAT: "{}/sidecar/windows/bin/packetbeat.exe".format(settings.FILE_PATH.rstrip("/")),
        METRICBEAT: "{}/sidecar/windows/bin/metricbeat.exe".format(settings.FILE_PATH.rstrip("/")),
    },
}

# YAML的项目路径
YAML_FILE_DIR = "apps/syslog/yaml"
# 采集器配置颜色 固定
COLOR = "#FFFFFF"

# graylog查询全量page_info
PAGE_INFO = {"page": 1, "per_page": 99999}

# 内置采集器
COLLECTORS = [
    {
        "name": "filebeat",
        "service_type": "exec",
        "node_operating_system": "linux",
        "executable_path": "/usr/local/gse/sidecar/bin/filebeat",
        "execute_parameters": "-c  %s",
        "validation_parameters": "test config -c %s",
        "default_template": "",
    },
    {
        "name": "winlogbeat",
        "service_type": "svc",
        "node_operating_system": "windows",
        "executable_path": "C:\\gse\\sidecar\\bin\\winlogbeat.exe",
        "execute_parameters": '-c "%s"',
        "validation_parameters": 'test config -c "%s"',
        "default_template": "",
    },
    {
        "name": "filebeat",
        "service_type": "svc",
        "node_operating_system": "windows",
        "executable_path": "C:\\gse\\sidecar\\bin\\filebeat.exe",
        "execute_parameters": '-c "%s"',
        "validation_parameters": 'test config -c "%s"',
        "default_template": "",
    },
    {
        "name": "uniprobe",
        "service_type": "exec",
        "node_operating_system": "linux",
        "executable_path": "/usr/local/gse/sidecar/bin/uniprobe",
        "execute_parameters": f"-i any -c 1 -d {GRAYLOG_URL.split('//')[1]}:12201 -j /use/local/gse/sidecar/json -y 100 -l /use/local/gse/sidecar/pcap -z 1000 -3 16384 -1 88332763814161 -r",  # noqa
        "validation_parameters": None,
        "default_template": "",
    },
    {
        "name": "auditbeat",
        "service_type": "exec",
        "node_operating_system": "linux",
        "executable_path": "/usr/local/gse/sidecar/bin/auditbeat",
        "execute_parameters": "-c  %s",
        "validation_parameters": "test config -c %s",
        "default_template": "",
    },
    {
        "name": "packetbeat",
        "service_type": "exec",
        "node_operating_system": "linux",
        "executable_path": "/usr/local/gse/sidecar/bin/packetbeat",
        "execute_parameters": "-c  %s",
        "validation_parameters": "test config -c %s",
        "default_template": "",
    },
    {
        "name": "packetbeat",
        "service_type": "svc",
        "node_operating_system": "windows",
        "executable_path": "C:\\gse\\sidecar\\bin\\packetbeat.exe",
        "execute_parameters": '-c "%s"',
        "validation_parameters": 'test config -c "%s"',
        "default_template": "",
    },
    {
        "name": "metricbeat",
        "service_type": "exec",
        "node_operating_system": "linux",
        "executable_path": "/usr/local/gse/sidecar/bin/metricbeat",
        "execute_parameters": "-c  %s",
        "validation_parameters": "test config -c %s",
        "default_template": "",
    },
    {
        "name": "metricbeat",
        "service_type": "svc",
        "node_operating_system": "windows",
        "executable_path": "C:\\gse\\sidecar\\bin\\metricbeat.exe",
        "execute_parameters": '-c "%s"',
        "validation_parameters": 'test config -c "%s"',
        "default_template": "",
    },
]

STREAM = "日志分组"

W_SIDECAR_DOWNLOAD_URL = f"{WEB_URL}openapi/download_file/?file_name=sidecar_windows.zip"
L_SIDECAR_DOWNLOAD_URL = f"{WEB_URL}openapi/download_file/?file_name=sidecar_linux.tar.gz"
L_INSTALL_DOWNLOAD_URL = f"{WEB_URL}openapi/download_file/?file_name=install_sidecar.sh"

BK_CLOUD_ID = "云区域"
BK_PROPERTY_NAME = ["内网IP", "实例名", "云区域", "录入方式"]