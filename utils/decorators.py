import json
import math
import time
from functools import wraps

import wrapt
from django.core.cache import cache
from django.views.generic.base import View

from utils import constants
from utils.app_log import api_logger, logger
from utils.exceptions import CustomApiException


class ApiLog(object):
    """
    decorator. log exception if task_definition has
    """

    def __init__(self, func_info=""):
        self.func_info = func_info

    def __call__(self, task_definition):
        @wraps(task_definition)
        def wrapper(*args, **kwargs):
            request = args[0]
            if isinstance(request, View):
                request = args[1]
            if request.method == "GET":
                params = json.dumps(getattr(request, "GET", None))
            else:
                try:
                    params = json.dumps(getattr(request, "data", None))
                except TypeError:
                    params = getattr(request, "data", None).get("file").name
                except Exception:
                    params = ""
            user = request.user.username
            ip = getattr(request, "current_ip", "")
            if not ip:
                ip = get_client_ip(request)
                setattr(request, "current_ip", ip)
            api_logger.info(
                f"[{ip}]使用帐号[{user}] 请求接口[{self.func_info}]，请求方法[{request.method}]，请求地址[{request.path}]，请求参数[{params}]"
            )
            return task_definition(*args, **kwargs)

        return wrapper


def get_client_ip(request):
    x_forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if x_forwarded_for:
        ip = x_forwarded_for.split(",")[-1].strip()
    else:
        ip = request.META.get("REMOTE_ADDR")
    return ip


def catch_exception(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception(e)
            logger.exception(f"[catch_exception] method name:{func.__name__} error")

        return None

    return wrapper


def cache_clear(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        fun = func(*args, **kwargs)
        cache.clear()
        logger.warning(f"[clear cache] method name:{func.__name__}")
        return fun

    return wrapper


# page扩展,获取全部数据,避免超过接口分页最大个数.
def extend_page(max_page_size=200, page_field="page", page_size_field="page_size"):
    def outer(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            page_size = kwargs.get(page_size_field, 10)
            page = kwargs.get(page_field, 1)
            count, data = func(*args, **kwargs)
            if count > max_page_size and page_size == constants.PAGE_SIZE_INFINITE_NUM and page == 1:
                total_page = math.ceil(count / max_page_size)  # type:int
                # 从第二批开始获取到最后并拼接至第一批
                for batch in range(2, total_page + 1):
                    kwargs.update({page_field: batch, page_size_field: max_page_size})
                    _, batch_data = func(*args, **kwargs)
                    data.extend(batch_data)
            elif page_size > max_page_size:
                raise ValueError("page_size数值过大,无法查询")
            return count, data

        return wrapper

    return outer


def get_all_page(max_count=200):
    def outer(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if not kwargs:
                limit = -1
            else:
                limit = kwargs.get("page", {}).get("limit", 10)
            count, data = 0, []
            if limit == -1:
                kwargs.get("page", {}).update(start=0)
                kwargs.get("page", {}).update(limit=max_count)
                while True:
                    count, _data = func(*args, **kwargs)
                    data.extend(_data or [])
                    if len(data) >= count:
                        break
                    kwargs["page"]["start"] += max_count
            else:
                count, data = func(*args, **kwargs)
            return count, data

        return wrapper

    return outer


def get_all_page_v2(max_count=200):
    def outer(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            page_size = kwargs.get("pagesize", 10)
            count, data = 0, []
            if page_size == -1:
                kwargs.update(page=1)
                kwargs.update(page_size=max_count)
                while True:
                    count, _data = func(*args, **kwargs)
                    data.extend(_data or [])
                    if len(data) >= count:
                        break
                    kwargs["page"] += max_count
            else:
                count, data = func(*args, **kwargs)
            return count, data

        return wrapper

    return outer


def delete_cache_key_decorator(clear_key):
    """
    删除指定key的缓存
    """

    @wrapt.decorator
    def wrapper(func, instance, args, kwargs):
        res = func(*args, **kwargs)

        try:
            cache.delete(key=clear_key)
        except Exception as err:
            logger.exception("删除缓存失败, key={}, error={}".format(clear_key, err))

        return res

    return wrapper


class WebTry(object):
    """
    decorator. log exception if task_definition has
    """

    def __init__(self, msg=""):
        self.msg = msg

    def __call__(self, task_definition):
        @wraps(task_definition)
        def wrapper(*args, **kwargs):
            try:
                return task_definition(*args, **kwargs)
            except CustomApiException as e:
                logger.error(e)
                return {"result": False, "message": self.msg}
            except Exception as e:
                logger.exception(e)
                return {"result": False, "message": self.msg}

        return wrapper


def time_consuming(func):
    """
    任务执行耗时计算
    """

    @wraps(func)
    def wrapper(*args, **kwargs):
        s_t = time.time()
        res = func(*args, **kwargs)
        e_t = time.time()
        logger.info("func_name={}, times ={}".format(getattr(func, "__name__", ""), e_t - s_t))
        return res

    return wrapper
