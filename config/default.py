# -*- coding: utf-8 -*-
"""
Tencent is pleased to support the open source community by making 蓝鲸智云PaaS平台社区版 (BlueKing PaaS Community
Edition) available.
Copyright (C) 2017-2020 THL A29 Limited, a Tencent company. All rights reserved.
Licensed under the MIT License (the "License"); you may not use this file except in compliance with the License.
You may obtain a copy of the License at
http://opensource.org/licenses/MIT
Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
"""
import importlib
import os  # noqa

from blueapps.conf.default_settings import *  # noqa
from blueapps.conf.log import get_logging_config_dict

# 请在这里加入你的自定义 APP

# 这里是默认的 INSTALLED_APPS，大部分情况下，不需要改动
# 如果你已经了解每个默认 APP 的作用，确实需要去掉某些 APP，请去掉下面的注释，然后修改
# INSTALLED_APPS = (
#     'bkoauth',
#     # 框架自定义命令
#     'blueapps.contrib.bk_commands',
#     'django.contrib.admin',
#     'django.contrib.auth',
#     'django.contrib.contenttypes',
#     'django.contrib.sessions',
#     'django.contrib.sites',
#     'django.contrib.messages',
#     'django.contrib.staticfiles',
#     # account app
#     'blueapps.account',
# )


INSTALLED_APPS += (  # noqa
    "version_log",
    "rest_framework",
    "rest_framework_swagger",
    "base_index",
    "casbin_adapter.apps.CasbinAdapterConfig",
)

# 这里是默认的中间件，大部分情况下，不需要改动
# 如果你已经了解每个默认 MIDDLEWARE 的作用，确实需要去掉某些 MIDDLEWARE，或者改动先后顺序，请去掉下面的注释，然后修改
# MIDDLEWARE = (
#     # request instance provider
#     'blueapps.middleware.request_provider.RequestProvider',
#     'django.contrib.sessions.middleware.SessionMiddleware',
#     'django.middleware.common.CommonMiddleware',
#     'django.middleware.csrf.CsrfViewMiddleware',
#     'django.contrib.auth.middleware.AuthenticationMiddleware',
#     'django.contrib.messages.middleware.MessageMiddleware',
#     # 跨域检测中间件， 默认关闭
#     # 'django.middleware.clickjacking.XFrameOptionsMiddleware',
#     'django.middleware.security.SecurityMiddleware',
#     # 蓝鲸静态资源服务
#     'whitenoise.middleware.WhiteNoiseMiddleware',
#     # Auth middleware
#     'blueapps.account.middlewares.RioLoginRequiredMiddleware',
#     'blueapps.account.middlewares.WeixinLoginRequiredMiddleware',
#     'blueapps.account.middlewares.LoginRequiredMiddleware',
#     # exception middleware
#     'blueapps.core.exceptions.middleware.AppExceptionMiddleware',
#     # django国际化中间件
#     'django.middleware.locale.LocaleMiddleware',
# )

# 自定义中间件
MIDDLEWARE += (  # noqa
    "utils.middlewares.CrossCSRF4WEOPS",
    "corsheaders.middleware.CorsMiddleware",
    "utils.middlewares.RequestMiddleware",
)

# 配置缓存
CACHES = locals()["CACHES"]
REDIS_PASSWORD = os.environ.get("BKAPP_REDIS_PASSWORD", "123456")
REDIS_HOST = os.environ.get("BKAPP_REDIS_HOST", "127.0.0.1")
REDIS_PORT = os.environ.get("BKAPP_REDIS_PORT", "6379")
REDIS_DB = os.environ.get("BKAPP_REDIS_DB", 0)
AUTO_MATE_REDIS_DB = os.environ.get("BKAPP_AUTO_MATE_REDIS_DB", 11)
# 去环境变量寻找登录方式，找不到就用keycloak
LOGIN_METHOD = os.environ.get("BKAPP_LOGIN_METHOD", "keycloak")
LOGIN_REDIRECT_URL = '/admin/' if LOGIN_METHOD == "local" else '/keycloak_login/'
KEYCLOAK_SETTINGS = {
    "KEYCLOAK_SERVER" : os.environ.get("BKAPP_KEYCLOAK_SERVER", "localhost"),
    "KEYCLOAK_PORT" : os.environ.get("BKAPP_KEYCLOAK_PORT", "8080"),
    "REALM_NAME" : os.environ.get("BKAPP_REALM_NAME", "master"),
    "CLIENT_ID" : os.environ.get("BKAPP_CLIENT_ID", "weops_lite"),
    "CLIENT_SECRET_KEY" : os.environ.get("BKAPP_CLIENT_SECRET_KEY", "UQym8RIjp4X4hxMxIkL1hOktVU1auDa3"),
}


try:
    importlib.import_module("django_redis")
except ImportError:
    pass
else:
    CACHES["redis"] = {
        "BACKEND": "django_redis.cache.RedisCache",
        "LOCATION": f"redis://:{REDIS_PASSWORD}@{REDIS_HOST}:{REDIS_PORT}/{REDIS_DB}",
        "OPTIONS": {
            "CLIENT_CLASS": "django_redis.client.DefaultClient",
            "COMPRESSOR": "django_redis.compressors.zlib.ZlibCompressor",
        }
    }

if "redis" in CACHES:
    CACHES["default"] = CACHES["redis"]
else:
    CACHES["default"] = CACHES["locmem"]

# 项目路径
PROJECT_PATH = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT, PROJECT_MODULE_NAME = os.path.split(PROJECT_PATH)
# 自定义上下文
if os.path.exists("config/template/context_processors.py"):
    CUSTOM_CONTEXT_PROCESSORS = [
        "config.template.context_processors.custom_settings",
    ]

    for tmpl in TEMPLATES:  # noqa
        tmpl["OPTIONS"]["context_processors"] += CUSTOM_CONTEXT_PROCESSORS

# CSRF Config
CSRF_COOKIE_NAME = "%s_csrftoken" % APP_CODE  # noqa
# 所有环境的日志级别可以在这里配置
# LOG_LEVEL = 'INFO'

# STATIC_VERSION_BEGIN
# 静态资源文件(js,css等）在APP上线更新后, 由于浏览器有缓存,
# 可能会造成没更新的情况. 所以在引用静态资源的地方，都把这个加上
# Django 模板中：<script src="/a.js?v={{ STATIC_VERSION }}"></script>
# 如果静态资源修改了以后，上线前改这个版本号即可
# STATIC_VERSION_END
STATIC_VERSION = "1.0"

STATICFILES_DIRS = [os.path.join(BASE_DIR, "static")]  # noqa

# CELERY 开关，使用时请改为 True，修改项目目录下的 Procfile 文件，添加以下两行命令：
# worker: python manage.py celery worker -l info
# beat: python manage.py celery beat -l info
# 不使用时，请修改为 False，并删除项目目录下的 Procfile 文件中 celery 配置
IS_USE_CELERY = True

# CELERY 并发数，默认为 2，可以通过环境变量或者 Procfile 设置
CELERYD_CONCURRENCY = os.getenv("BK_CELERYD_CONCURRENCY", 4)  # noqa

# CELERY 配置，申明任务的文件路径，即包含有 @task 装饰器的函数文件
CELERY_IMPORTS = ()

DEFAULT_CELERY_SHORT_TIMEDELTA = os.getenv("BKAPP_DEFAULT_CELERY_SHORT_TIMEDELTA", 5 * 60)

# load logging settings
LOGGING = get_logging_config_dict(locals())

# 初始化管理员列表，列表中的人员将拥有预发布环境和正式环境的管理员权限
# 注意：请在首次提测和上线前修改，之后的修改将不会生效
INIT_SUPERUSER = []

# BKUI是否使用了history模式
IS_BKUI_HISTORY_MODE = False

# 是否需要对AJAX弹窗登录强行打开
IS_AJAX_PLAIN_MODE = False

# 国际化配置
LOCALE_PATHS = (os.path.join(BASE_DIR, "locale"),)  # noqa

TIME_ZONE = "Asia/Shanghai"
LANGUAGE_CODE = "zh-hans"

LANGUAGES = (
    ("en", "English"),
    ("zh-hans", "简体中文"),
)

# 控制台绑定微信的类型(wx微信,qywx企业微信)
CONSOLE_BIND_WX_TYPE = os.getenv("BKAPP_CONSOLE_BIND_WX_TYPE", "wx")

# 微信公众号配置
WX_APP_ID = os.getenv("BKAPP_WEIXIN_APP_ID", "")
WX_APP_SECRET = os.getenv("BKAPP_WEIXIN_APP_SECRET", "")
WECHAT_SETTING = {"appid": WX_APP_ID, "appsecret": WX_APP_SECRET}
WX_ENVENT_NAME = os.getenv("BKAPP_WX_ENVENT_NAME", "weops事件管理")

# cmdb 路径配置
CMDB_URL = os.getenv("BKAPP_CMDB_HREF", "http://cmdb.weops.com/").strip("/") + "/"
# 作业平台 路径配置
JOB_URL = os.getenv("BKAPP_JOB_HREF", "http://job.weops.com/").strip("/") + "/"
# weops app code
WEOPS_CODE = os.getenv("BKAPP_WEOPS_CODE", "weops_saas")
# 当前环境（t/o）
CURRENT_ENV = "o" if os.getenv("BK_ENV") == "production" else "t"

# 线程池线程个数
THREAD_POOL_MAX_WORKERS = os.getenv("BKAPP_THREAD_POOL_MAX_WORKERS", "8")

# WeOps目录地址，用来存放远程管理上传的文件
UPLOAD_FILES_PATH = os.getenv("BKAPP_FILE_UPLOAD_PATH", "/data/bkce/public/paas_agent/share/weops_saas/")
SOURCE_IP = os.getenv("BKAPP_SOURCE_IP", "10.10.25.169")
BK_CLOUD_ID = os.getenv("BKAPP_BK_CLOUD_ID", "0")

CURRENT_FILE_PATH = "USERRES"  # 存放文件路径

if not os.path.exists(CURRENT_FILE_PATH):
    os.makedirs(CURRENT_FILE_PATH)

"""
以下为框架代码 请勿修改
"""
# celery settings
if IS_USE_CELERY:
    INSTALLED_APPS = locals().get("INSTALLED_APPS", [])
    import djcelery

    INSTALLED_APPS += ("djcelery",)
    djcelery.setup_loader()
    CELERY_ENABLE_UTC = False
    CELERYBEAT_SCHEDULER = "djcelery.schedulers.DatabaseScheduler"

# remove disabled apps
if locals().get("DISABLED_APPS"):
    INSTALLED_APPS = locals().get("INSTALLED_APPS", [])
    DISABLED_APPS = locals().get("DISABLED_APPS", [])

    INSTALLED_APPS = [_app for _app in INSTALLED_APPS if _app not in DISABLED_APPS]

    _keys = (
        "AUTHENTICATION_BACKENDS",
        "DATABASE_ROUTERS",
        "FILE_UPLOAD_HANDLERS",
        "MIDDLEWARE",
        "PASSWORD_HASHERS",
        "TEMPLATE_LOADERS",
        "STATICFILES_FINDERS",
        "TEMPLATE_CONTEXT_PROCESSORS",
    )

    import itertools

    for _app, _key in itertools.product(DISABLED_APPS, _keys):
        if locals().get(_key) is None:
            continue
        locals()[_key] = tuple(_item for _item in locals()[_key] if not _item.startswith(_app + "."))

# ==============================================================================
# REST FRAMEWORK SETTING
# ==============================================================================
REST_FRAMEWORK = {
    "DEFAULT_PERMISSION_CLASSES": ("rest_framework.permissions.IsAuthenticated",),
    "DEFAULT_PAGINATION_CLASS": "packages.drf.pagination.CustomPageNumberPagination",
    "PAGE_SIZE": 10,
    "TEST_REQUEST_DEFAULT_FORMAT": "json",
    # "DEFAULT_AUTHENTICATION_CLASSES": ("rest_framework.authentication.SessionAuthentication",),
    "DEFAULT_FILTER_BACKENDS": (
        "django_filters.rest_framework.DjangoFilterBackend",
        "rest_framework.filters.SearchFilter",
        "rest_framework.filters.OrderingFilter",
    ),
    "DATETIME_FORMAT": "%Y-%m-%d %H:%M:%S",
    "NON_FIELD_ERRORS_KEY": "params_error",
    "DEFAULT_RENDERER_CLASSES": ("packages.drf.renderers.CustomRenderer",),
    "DEFAULT_SCHEMA_CLASS": "rest_framework.schemas.coreapi.AutoSchema",
    # "EXCEPTION_HANDLER": "utils.exception_capture.common_exception_handler",
}
if LOGIN_METHOD == 'keycloak':
    REST_FRAMEWORK['DEFAULT_AUTHENTICATION_CLASSES'] = ('apps.system_mgmt.KeycloakTokenAuthentication'
                                                        '.KeycloakTokenAuthentication',)

HAYSTACK_CONNECTIONS = {
    "default": {
        # 使用whoosh引擎
        "ENGINE": "haystack.backends.whoosh_backend.WhooshEngine",
        # 索引文件路径
        "PATH": os.path.join(BASE_DIR, "USERRES", "whoosh_index"),  # noqa
    }
}
PROFILE_BUCKET = "weops-profile-private"  # 配置文件桶
MINIO_PRIVATE_BUCKETS = [
    PROFILE_BUCKET,
]
