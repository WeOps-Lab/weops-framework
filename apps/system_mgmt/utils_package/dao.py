# -*- coding: utf-8 -*-

# @File    : dao.py
# @Date    : 2022-03-25
# @Author  : windyzhao
from django.db.models import QuerySet

from apps.system_mgmt.constants import DB_NORMAL_USER
from apps.system_mgmt.models import SysRole, SysUser
from utils import constants


class ModelOperate(object):
    @classmethod
    def get_user(cls, *args, **kwargs):
        username = kwargs["username"]
        user = SysUser.objects.get(bk_username=username)
        return user

    @classmethod
    def model_create(cls, *args, **kwargs):
        model_objects = kwargs["model_objects"]
        instance_data = kwargs["data"]
        instance = model_objects.objects.create(**instance_data)

        return instance

    @classmethod
    def filter_queryset(cls, *args, **kwargs):
        filters = kwargs["filters"]
        model_objects = kwargs["model_objects"]

        queryset = model_objects.objects.filter(**filters)

        return queryset

    @classmethod
    def create(cls, *args, **kwargs):
        model_manage = kwargs["model_manage"]
        instance_data = kwargs["data"]
        serializer = model_manage.get_serializer(data=instance_data)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return serializer

    @classmethod
    def model_update(cls, *args, **kwargs):
        instance_data = kwargs["data"]
        instance = kwargs["instance"]

        for field, values in instance_data.items():
            setattr(instance, field, values)

        instance.save()

    @classmethod
    def update(cls, *args, **kwargs):
        instance = kwargs["instance"]
        instance_data = kwargs["data"]
        model_manage = kwargs["model_manage"]
        serializer = model_manage.get_serializer(instance=instance, data=instance_data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return serializer

    @classmethod
    def delete(cls, *args, **kwargs):
        instance = kwargs["instance"]
        instance.delete()

    @classmethod
    def add_many_to_many_field(cls, *args, **kwargs):
        """
        多对多关系添加
        """
        instance = kwargs["instance"]
        add_data = kwargs["add_data"]
        add_attr = kwargs["add_attr"]
        attr = getattr(instance, add_attr)
        if isinstance(add_data, QuerySet):
            attr.add(*add_data)
        else:
            attr.add(add_data)
        return True

    @classmethod
    def update_many_to_many_field(cls, *args, **kwargs):
        """
        多对多关系修改
        先删除原先的关联 再设置（因为传递的是全部）
        """
        instance = kwargs["instance"]
        add_data = kwargs["add_data"]
        add_attr = kwargs["add_attr"]
        attr = getattr(instance, add_attr)
        attr.set(add_data)

        return True

    @classmethod
    def delete_many_to_many_field(cls, *args, **kwargs):
        """
        多对多关系删除
        """
        instance = kwargs["instance"]
        delete_data = kwargs["delete_data"]
        delete_attr = kwargs["delete_attr"]
        attr = getattr(instance, delete_attr)
        attr.remove(delete_data)
        return True


class UserModels(ModelOperate):
    @classmethod
    def delete_user(cls, user):
        user.delete()

    @classmethod
    def get_user_objects(cls, user_id):
        user_obj = SysUser.objects.get(id=user_id)
        return user_obj

    @classmethod
    def get_normal_user(cls):
        """
        获取普通用户
        """
        normal_user = SysRole.objects.get(role_name=DB_NORMAL_USER)
        return normal_user

    @classmethod
    def user_update_bk_user_id(cls, *args, **kwargs):
        """
        更新用户的bk_user_id字段
        """
        instance = kwargs["instance"]
        bk_user_id = kwargs["bk_user_id"]
        instance.bk_user_id = bk_user_id
        instance.save()

        return True

    @classmethod
    def get_user_admin_bool(cls, *args, **kwargs):
        """
        判断此用户是否为admin
        """
        self = kwargs["self"]
        _id = kwargs["id"]
        search_field = kwargs["field"]
        admin_bool = self.queryset.get(**{search_field: _id}).bk_username in constants.ADMIN_USERNAME_LIST
        return admin_bool

    @classmethod
    def user_set_roles(cls, *args, **kwargs):
        """
        给用户设置角色
        """
        user_obj = kwargs["user_obj"]
        roles_ids = kwargs["roles_ids"]
        roles = SysRole.objects.filter(id__in=roles_ids)
        user_obj.roles.set(roles)
        return roles
