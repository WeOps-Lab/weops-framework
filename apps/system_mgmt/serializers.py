import base64

from django.db import transaction
from rest_framework import serializers
from rest_framework.fields import empty
from rest_framework.relations import RelatedField
from rest_framework.serializers import ModelSerializer

from apps.system_mgmt.constants import DB_SUPER_USER, PERMISSIONS_MAPPING
from apps.system_mgmt.models import InstancesPermissions, MenuManage, OperationLog, SysRole, SysSetting, SysUser
from apps.system_mgmt.sys_setting import serializer_value
from utils.tools import UploadFileUtils


class LogSerializer(ModelSerializer):
    file = serializers.ImageField(max_length=None, allow_null=True, required=False, write_only=True)

    class Meta:
        model = SysSetting
        fields = ("key", "value", "file")
        extra_kwargs = {"key": {"read_only": True}, "value": {"read_only": True}}

    def __init__(self, instance=None, data=empty, **kwargs):
        super().__init__(instance=instance, data=data, **kwargs)
        self.img_base64 = ""

    def validate_file(self, file_obj):
        UploadFileUtils(file_obj).image_file_check()
        self.img_base64 = base64.b64encode(file_obj.read()).decode("utf8")
        return file_obj

    @transaction.atomic
    def update(self, instance, validated_data):
        username = self.context["request"].user.get('username', None)
        validated_data["value"] = self.img_base64
        validated_data.pop("file")
        OperationLog.create_log([instance], OperationLog.MODIFY, username, "修改系统logo")
        return super().update(instance, validated_data)


class OperationLogSer(ModelSerializer):
    class Meta:
        model = OperationLog
        fields = "__all__"


class SysSettingValueField(RelatedField):
    def get_queryset(self):
        return SysSetting.objects.all()

    def to_internal_value(self, data):
        return data

    def to_representation(self, value):
        return value


class SysSettingSer(ModelSerializer):
    value = SysSettingValueField()
    real_value = serializers.SerializerMethodField()

    class Meta:
        model = SysSetting
        fields = "__all__"

    @staticmethod
    def get_real_value(obj):
        return obj.real_value

    def to_representation(self, instance):
        k = super(SysSettingSer, self).to_representation(instance)
        k.update(value=k.pop("real_value", None))
        return k

    def validate(self, attrs):
        vtype = attrs.get("vtype")
        value = attrs.get("value")
        if vtype not in SysSetting.VTYPE_FIELD_MAPPING:
            raise serializers.ValidationError(
                f"vtype:{vtype} error. must be in {list(SysSetting.VTYPE_FIELD_MAPPING.keys())}"
            )
        func = SysSetting.VTYPE_FIELD_MAPPING.get(vtype, SysSetting.VTYPE_FIELD_MAPPING[SysSetting.DEFAULT])
        try:
            func().to_python(value)
            return attrs
        except Exception:
            raise serializers.ValidationError(f"value:{value} type error.the type must be a {vtype}")

    def to_internal_value(self, data):
        ret = super(SysSettingSer, self).to_internal_value(data)
        user_name = self.context["request"].user.username
        if self.instance:
            ret["updated_by"] = user_name
        else:
            ret["created_by"] = user_name
        ret["value"] = serializer_value(data["value"], data["vtype"])
        return ret


class AutoField(serializers.Field):
    def to_internal_value(self, data):
        return data

    def to_representation(self, value):
        return dict(SysUser.SEX_CHOICES)[value]


class SysUserSerializer(ModelSerializer):
    roles = serializers.SerializerMethodField()
    leaders = serializers.SerializerMethodField()

    # sexuality = AutoField()
    def __init__(self, instance=None, data=empty, **kwargs):
        super(SysUserSerializer, self).__init__(instance, data, **kwargs)
        if isinstance(instance, SysUser):
            role_list = instance.roles.all().values("sysuser", "id")
        elif instance is None:
            role_list = []
        else:
            role_list = SysRole.objects.filter(sysuser__in=[i.id for i in instance]).values("sysuser", "id")
        role_map = {}
        for i in role_list:
            role_map.setdefault(i["sysuser"], []).append(i["id"])
        self.role_map = role_map

        self.sys_user_dict = {}
        if isinstance(instance, list):
            _bk_user_ids = []
            for _instance in instance:
                for _leader in _instance.leader:
                    if isinstance(_leader, int):
                        _bk_user_ids.append(_leader)
                    elif isinstance(_leader, dict):
                        _bk_user_ids.append(_leader["id"])

            _sys_user_list = SysUser.objects.filter(bk_user_id__in=_bk_user_ids).values(
                "bk_user_id", "chname", "bk_username"
            )
            for _sys_user_data in _sys_user_list:
                self.sys_user_dict[_sys_user_data["bk_user_id"]] = _sys_user_data

    class Meta:
        model = SysUser
        fields = (
            "id",
            "bk_user_id",
            "bk_username",
            "chname",
            "email",
            "phone",
            "roles",
            "local",
            "departments",
            "leader",
            "leaders",
            "status",
        )
        extra_kwargs = {
            "leader": {"write_only": True},
        }

    def get_roles(self, obj):
        """
        获取此用户拥有的角色id
        """
        return self.role_map.get(obj.id, [])

    def get_leaders(self, obj):
        res = []
        for leader in obj.leader:
            if isinstance(leader, dict):
                leader = leader["id"]
            data = self.sys_user_dict.get(leader)
            if not data:
                continue
            res.append(data)
        return res


class SysRoleSerializer(ModelSerializer):
    is_super = serializers.SerializerMethodField()
    users = serializers.SerializerMethodField()

    class Meta:
        model = SysRole
        fields = ("id", "role_name", "describe", "built_in", "is_super", "created_at", "users")

    @staticmethod
    def get_is_super(obj):
        return obj.role_name == DB_SUPER_USER

    @staticmethod
    def get_users(obj):
        res = [
            {"id": i.id, "bk_user_id": i.bk_user_id, "bk_username": i.bk_username, "chname": i.chname}
            for i in obj.sysuser_set.all()
        ]
        return res


class MenuManageModelSerializer(ModelSerializer):
    class Meta:
        model = MenuManage
        fields = "__all__"


class InstancesPermissionsModelSerializer(ModelSerializer):
    count = serializers.SerializerMethodField()
    permissions_text = serializers.SerializerMethodField()

    @staticmethod
    def get_count(instance):
        return len(instance.instances)

    @staticmethod
    def get_permissions_text(instance):
        return ",".join([PERMISSIONS_MAPPING[k] for k, v in instance.permissions.items() if v and k != "bk_obj_id"])

    class Meta:
        model = InstancesPermissions
        fields = "__all__"
        extra_kwargs = {
            "instances": {"write_only": True},
            "permissions": {"write_only": True},
        }
