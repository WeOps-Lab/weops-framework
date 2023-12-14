# -*- coding: utf-8 -*-

# @File    : minio_utils.py
# @Date    : 2022-05-05
# @Author  : windyzhao

import datetime
from datetime import timedelta

import filetype
from django.conf import settings
from minio import Minio
from minio.commonconfig import CopySource
from minio.deleteobjects import DeleteObject

from utils.app_log import logger


class MinIoClient(object):
    """
    minio服务类 手动操作minio

    endpoint	对象存储服务的URL。
    access_key	Access key是唯一标识你的账户的用户ID。
    secret_key	Secret key是你账户的密码。
    secure	true代表使用HTTPS。
    """

    # __instance = None
    #
    # def __new__(cls, *args, **kwargs):
    #     if cls.__instance is None:
    #         cls.__instance = object.__new__(cls)
    #     return cls.__instance

    def __init__(self, minio_client=False):
        if settings.DEBUG:
            self.endpoint = "127.0.0.1:9001"
            self.access_key = "admin"
            self.secret_key = "1234567890"
            self.secure = False
        else:
            self.access_key = settings.MINIO_ACCESS_KEY
            self.secret_key = settings.MINIO_SECRET_KEY
            self.endpoint = settings.MINIO_EXTERNAL_ENDPOINT
            self.secure = settings.MINIO_EXTERNAL_ENDPOINT_USE_HTTPS

        # 构造函数
        if minio_client:
            self.minio_client = minio_client
        else:
            self.minio_client = Minio(
                self.endpoint, access_key=self.access_key, secret_key=self.secret_key, secure=self.secure
            )

    @staticmethod
    def get_file_content_type(file_path: str):
        """
        获取文件的 content_type
        """
        try:
            guess = filetype.guess(file_path)
            file_type = guess.MIME
        except Exception as err:
            logger.exception("获取文件{}的content_type失败,error={}".format(file_path, err))
            file_type = "application/octet-stream"

        return file_type

    # 操作存储桶
    def make_bucket(self, bucket_name: str):
        """
        创建一个存储桶
        :param bucket_name: 存储桶名称
        :return:
        """
        try:
            self.minio_client.make_bucket(bucket_name=bucket_name)
        except Exception as err:
            logger.exception("创建桶失败:{}".format(err))
            return False
        return True

    def bucket_exists(self, bucket_name: str):
        """
        检查存储桶是否存在
        :param bucket_name:存储桶名称
        :return:
        """
        try:
            res = self.minio_client.bucket_exists(bucket_name)
        except Exception as err:
            logger.exception("检查存储桶是否存在错误:{}".format(err))
            return False
        return res

    def remove_bucket(self, bucket_name: str):
        """
        删除桶
        :param bucket_name: 存储桶名称
        :return:
        """
        try:
            self.minio_client.remove_bucket(bucket_name)
        except Exception as err:
            logger.exception("删除桶失败:{}".format(err))
            return False
        return True

    def list_buckets(self):
        """
        列出所有的存储桶
        :return: list
        """
        result = True
        try:
            buckets = self.minio_client.list_buckets()
        except Exception as err:
            logger.exception("列出所有的存储桶失败:{}".format(err))
            result = False
            buckets = []

        res = [
            {
                "bucket_name": bucket.name,
                "creation_date": datetime.datetime.astimezone(bucket.creation_date).strftime("%Y-%m-%d %H:%M:%S"),
            }
            for bucket in buckets
        ]

        return {"result": result, "res": res}

    # 操作对象
    def list_objects(self, bucket_name: str, recursive: bool = False, prefix=None):
        """
        列出存储桶中所有对象
        :return:
        """
        result = True
        try:
            objects = self.minio_client.list_objects(bucket_name, prefix=prefix, recursive=recursive)
        except Exception as err:
            logger.exception("列出存储桶中所有对象失败:{}".format(err))
            objects = []
            result = False

        data = [
            {
                "bucket_name": obj.bucket_name,
                "object_name": obj.object_name.encode("utf-8"),
                "last_modified": obj.last_modified,
                "etag": obj.etag,
                "size": obj.size,
                "content_type": obj.content_type,
            }
            for obj in objects
        ]

        return {"result": result, "data": data}

    def get_object(self, bucket_name: str, object_name: str, file_path: str = ""):
        """
        下载一个对象
        :param bucket_name:存储桶名称
        :param object_name:对象名称
        :param file_path:存储路径
        :return:
        """
        try:
            data = self.minio_client.get_object(bucket_name=bucket_name, object_name=object_name)
            if file_path:
                with open(file_path, "wb") as file_data:
                    for d in data.stream(32 * 1024):
                        file_data.write(d)
        except Exception as err:
            logger.exception("下载一个文件对象失败:{}".format(err))
            return False
        return data

    def put_object(
        self,
        bucket_name: str,
        object_name: str,
        data: object,
        length: int,
        content_type: str = "application/octet-stream",
    ):
        """
        添加一个新的对象到对象存储服务。
        注意：本API支持的最大文件大小是5TB。
        上传的对象 必须使用读取为io.RawIOBase的python对象
        put_object在对象大于5MiB时，自动使用multiple parts方式上传。
        这样，当上传失败时，客户端只需要上传未成功的部分即可（类似断点上传）。上传的对象使用MD5SUM签名进行完整性验证。
        :param bucket_name: 存储桶名称。
        :param object_name: 对象名称。
        :param data: 任何实现了io.RawIOBase的python对象。 一个具有可调用read()返回bytes对象的对象。
        :param length: 对象的总长度。
        :param content_type: 对象的Content type。（可选，默认是“application/octet-stream”）
        :return: etag:
        """
        logger.info("minio put_object bucket_name={} object_name={}".format(bucket_name, object_name))
        try:
            etag = self.minio_client.put_object(
                bucket_name=bucket_name, object_name=object_name, data=data, length=length, content_type=content_type
            )
        except Exception as err:
            logger.exception("添加一个新的对象到对象存储服务失败:{}".format(err))
            return False
        return etag

    def fput_object(self, bucket_name: str, object_name: str, file_path: str):
        """
        通过文件上传到对象中
        注意：本API支持的最大文件大小是5TB。
        上传的对象 必须使用读取为io.RawIOBase的python对象
        put_object在对象大于5MiB时，自动使用multiple parts方式上传。
        这样，当上传失败时，客户端只需要上传未成功的部分即可（类似断点上传）。上传的对象使用MD5SUM签名进行完整性验证。
        :param bucket_name: 存储桶名称。
        :param object_name: 对象名称。
        :param file_path: 本地文件的路径，会将该文件的内容上传到对象存储服务上。
        :return: etag:
        """
        try:
            content_type = self.get_file_content_type(file_path=file_path)
            etag = self.minio_client.fput_object(
                bucket_name=bucket_name, object_name=object_name, file_path=file_path, content_type=content_type
            )
        except Exception as err:
            logger.exception("通过文件上传到对象存储服务失败:{}".format(err))
            return ""
        return etag

    def remove_object(self, bucket_name: str, object_name: str):
        """
        删除一个对象
        :param bucket_name:存储桶名称
        :param object_name:对象名称
        :return:
        """

        try:
            self.minio_client.remove_object(bucket_name=bucket_name, object_name=object_name)
        except Exception as err:
            logger.exception("删除一个文件对象失败:{}".format(err))
            return False
        return True

    def remove_objects(self, bucket_name: str, objects_iter: list):
        """
        删除存储桶中的多个对象
        :param bucket_name: 存储桶名称。
        :param objects_iter: 多个对象名称的列表数据。
        :return:
        """
        delete_errors = []
        result = True
        delete_object_list = [DeleteObject(i) for i in objects_iter]
        try:
            for delete_error in self.minio_client.remove_objects(
                bucket_name=bucket_name, delete_object_list=delete_object_list
            ):
                delete_errors.append(delete_error)
        except Exception as err:
            logger.exception("删除存储桶中的多个对象失败:{}".format(err))
            result = False

        return {"result": result, "delete_errors": delete_errors}

    def copy_object(self, new_bucket, new_object, source_bucket, source_object):
        """
        对象复制
        """
        try:
            result = self.minio_client.copy_object(new_bucket, new_object, CopySource(source_bucket, source_object),)
        except Exception as e:
            logger.exception("oss对象复制出错, error={}".format(e))
            result = False

        return result

    def stat_object(self, bucket_name: str, object_name: str):
        """
        查询对象元数据
        :param bucket_name: 存储桶名称
        :param object_name: 对象名称
        """
        try:
            res = self.minio_client.stat_object(bucket_name=bucket_name, object_name=object_name)
        except Exception as e:
            logger.exception("oss查询对象元数据, error={}".format(e))
            res = False

        return res

    # Presigned操作
    def presigned_get_object(self, bucket_name: str, object_name: str, expiry=timedelta(days=7)):
        """
        生成一个用于HTTP GET操作的presigned URL。浏览器/移动客户端可以在即使存储桶为私有的情况下也可以通过这个URL进行下载。
        这个presigned URL可以有一个过期时间，默认是7天。
        :param bucket_name: 存储桶名称
        :param object_name: 对象名称
        :param expiry: 过期时间，单位是秒，默认是7天
        :return:
        """

        result = True
        try:
            res = self.minio_client.presigned_get_object(bucket_name, object_name.encode("utf-8"), expires=expiry)
        except Exception as err:
            logger.exception("生成一个对象的HTTP URL 失败:{}".format(err))
            res = ""
            result = False

        return {"result": result, "data": res}
