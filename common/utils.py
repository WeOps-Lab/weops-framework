# -- coding: utf-8 --
from blueapps.core.exceptions import ServerBlueException

# @File : utils.py
# @Time : 2023/4/19 15:37
# @Author : windyzhao


def split_list(_list, count=100):
    n = len(_list)
    sublists = [_list[i : i + count] for i in range(0, n, count)]
    return sublists


def corntab_format(value_type: str, value: str):
    """将数据转换成crontab格式"""
    is_interval = True
    if value_type == "cycle":
        scan_cycle = "0 */{} * * *".format(int(value))
    elif value_type == "timing":
        time_data = value.split(":")
        if len(time_data) != 2:
            raise ServerBlueException("定时时间格式错误！")
        scan_cycle = "{} {} * * *".format(int(time_data[1]), int(time_data[0]))
    elif value_type == "close":
        scan_cycle = ""
        is_interval = False
    else:
        raise ServerBlueException("定时类型错误！")
    return is_interval, scan_cycle
