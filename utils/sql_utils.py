import os

import pymysql
from django.conf import settings
from django.db import connection
from MySQLdb.cursors import DictCursor

from blueapps.utils.logger import logger


# 直连数据库查询类
class SQLClient(object):
    def __init__(self, db_name):
        if os.getenv("BK_ENV") == "testing" and db_name != "bk_user":
            db_name += "_bkt"
        db_config = connection.get_connection_params()
        db_config["db"] = db_name
        if settings.DEBUG:
            if hasattr(settings, "DB_CONFIG"):
                db_config.update(settings.DB_CONFIG)
        self.connection = connection.get_new_connection(db_config)

    def disconnect(self):
        """
        断开连接
        """
        self.connection.close()

    def execute_mysql_sql(self, sql, args=None, get_result=True):
        """
        执行SQL
        """
        cursor = self.connection.cursor(DictCursor)
        try:
            if isinstance(args, str):
                args = [args]
            elif isinstance(args, int):
                args = [str(args)]
            cursor.execute(sql, args)
            if get_result:
                result = list(cursor.fetchall())
            else:
                self.connection.commit()
                result = []
        except Exception as e:
            logger.error(f"执行SQL【{sql}】异常")
            logger.exception(e)
            result = []
        cursor.close()
        return result

    def execute_sql_list(self, sql, args):
        """
        执行多条SQL
        """
        cursor = self.connection.cursor(DictCursor)
        try:
            cursor.executemany(sql, args)
        except Exception as e:
            logger.exception(e)
        cursor.close()

    def execute_fun(self, fun_name):
        fun = getattr(self, fun_name, None)
        result = None
        if fun:
            result = fun()
        self.disconnect()
        return result


class NativeSql(object):
    """
    执行原生sql
    """

    def __init__(self, host, user, password, port=3306):
        # 未指定db 使用前先self.connection.select_db(db) # db为库名称
        self.cursor = None
        self.connection = pymysql.connect(host=host, user=user, password=password, port=port)

    def get_cursor(self, db):
        """
        使用对应的数据库，返回游标
        """
        self.connection.select_db(db)
        self.cursor = self.connection.cursor()

    def execute_sql_one(self, sql):
        """
        执行sql 返回单条
        """
        self.cursor.execute(sql)
        return self.cursor.fetchone()

    def execute_sql(self, sql):
        """
        执行sql 查询
        """
        self.cursor.execute(sql)
        return self.cursor.fetchall()

    def create_sql(self, sql):
        """
        新增
        """
        self.cursor.execute(sql)

    def update_sql(self, sql):
        """
        修改
        """
        self.cursor.execute(sql)

    def delete_sql(self, sql):
        """
        删除
        """
        self.cursor.execute(sql)

    def close_cursor(self):
        """
        关闭游标
        """
        self.cursor.close()

    def close_connection(self):
        """
        关闭连接
        """
        self.connection.close()

    def commit(self):
        """
        提交执行
        """
        self.connection.commit()

    def rollback(self):
        """
        提交回滚
        """
        self.connection.rollback()
