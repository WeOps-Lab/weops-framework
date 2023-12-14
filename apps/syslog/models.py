from django.db import models
from django_mysql.models import JSONField

from utils.common_models import MaintainerInfo, TimeInfo


class AlarmStrategy(TimeInfo, MaintainerInfo):
    event_definition_id = models.CharField(verbose_name="告警事件ID", max_length=200, unique=True, default="")
    title = models.CharField(verbose_name="策略标题", max_length=200, db_index=True, default="")
    is_scheduled = models.BooleanField(verbose_name="是否开启", default=True)

    class Meta:
        verbose_name = "告警策略"


class Node(TimeInfo, MaintainerInfo):
    node_name = models.CharField(unique=True, max_length=200, default="", help_text="节点名称")
    bk_host_id = models.IntegerField(unique=True, default=0, help_text="实例ID")
    is_manual = models.BooleanField(default=False, help_text="是否手动")

    class Meta:
        verbose_name = "探针节点"


class ProbeJob(TimeInfo, MaintainerInfo):

    probe_type = models.CharField(default="", max_length=100, help_text="探针类型")
    action = models.CharField(default="", max_length=100, help_text="操作")
    job_id = models.BigIntegerField(db_index=True, default=0, help_text="作业实例ID")
    job_code = models.SmallIntegerField(db_index=True, default=0, help_text="作业状态码")
    node = models.ForeignKey(Node, on_delete=models.CASCADE, help_text="探针ID")
    message = models.TextField(default={}, help_text="message")

    class Meta:
        verbose_name = "探针任务"


class Stream(TimeInfo, MaintainerInfo):
    id = models.CharField(primary_key=True, max_length=100, help_text="数据流ID")
    title = models.CharField(db_index=True, max_length=200, help_text="数据流标题")

    class Meta:
        verbose_name = "数据流"


class RoleStream(models.Model):
    role_id = models.IntegerField(primary_key=True, help_text="角色ID")
    stream_list = JSONField(default=list, help_text="数据流列表")
