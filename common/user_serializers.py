from rest_framework import serializers
from rest_framework.fields import empty

from common.sys_user_utils import user_cache


class UserCNNameSerializers(serializers.ModelSerializer):
    created_by_cn = serializers.SerializerMethodField()
    updated_by_cn = serializers.SerializerMethodField()

    def __init__(self, instance=None, data=empty, **kwargs):
        super(UserCNNameSerializers, self).__init__(instance, data, **kwargs)
        self.user_map = user_cache()

    def get_created_by_cn(self, instance):
        return self.user_map.get(instance.created_by) or instance.created_by

    def get_updated_by_cn(self, instance):
        return self.user_map.get(instance.updated_by) or instance.updated_by