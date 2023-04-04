# WeOPS-Framework

<img src="https://wedoc.canway.net/imgs/img/嘉为蓝鲸.jpg" >


#### 更多资料/工具包下载可见“蓝鲸 S-mart市场”
https://bk.tencent.com/s-mart/application/282/detail

#### 更多问题欢迎添加“小嘉”微信，加入官方沟通群

<img src="https://wedoc.canway.net/imgs/img/小嘉.jpg" width="30%" height="30%">


# 嘉为蓝鲸WeOPS基础框架使用说明

## 开发使用

### 框架目录
```markdown
├── apps # 内置应用代码
├── apps_other # 自定义添加应用代码
├── base_index # 首页入口文件
├── blueapps # 蓝鲸内置应用
├── blueking # 蓝鲸API网关接口
├── config  # 配置文件
│    ├── template # 首页变量模板
│    ├── __init__.py # 基础配置文件
│    ├── default.py # 基础配置文件
│    ├── dev.py # 本地开发配置文件
│    ├── envs.json # 环境变量配置
│    ├── prod.py # 正式环境配置文件
│    ├── stag.py # 测试环境配置文件
├── locale # 语言包
├── packages # drf 配置
├── scripts # 脚本文件
│    ├── check_migrate # 校验提交模型字段
│    ├── check_commit_message.py # 校验提交信息是否包含规范的前缀
│    ├── check_requirements # 校验 requirements 是否符合要求
├── templates
├── utils # 内置工具包
├── .flake8 # flake8 效验规则配置
├── .gitignore
├── .isort.cfg # isort 规则
├── .pre-commit-config.yaml # pre-commit 配置
├── __init__.py
├── LICENSE
├── manage.py # 入口文件
├── pyproject.toml 
├── README.md
├── requirements.txt # 应用依赖包
├── runtime.txt # 应用运行python版本要求
├── settings.py # 应用基础配置文件
├── urls.py # 路由文件
├── wsgi.py # wsgi 配置启动
```



### 分支管理

- main

main 是主分支。

### 集成工具说明

#### pre-commit

pre-commit 是基于 Git Hooks 的本地开发套件，支持通过插件扩展能力。目前支持 PEP8 规范检查、代码格式化、commit 信息检查、
requirements.txt 包检查等功能。


### 功能开发

#### 环境安装

> 可使用pipenv,virtualenv,anaconda,此处仅演示anaconda

```shell
# 创建3.6虚拟环境
conda create --name auto-mate python=3.6
# 进入虚拟环境
conda activate venv
# 安装环境所需pip包
pip install -r requirements.txt -i https://mirrors.aliyun.com/pypi/simple/
# 安装pre-commit
pip install pre-commit
pre-commit install --allow-missing-config
pre-commit install --hook-type commit-msg --allow-missing-config
```
#### 正式开发
1、在`apps_other`目录下新建python包，包名必须以`app_` 开头
![新建python包](./docs/img/create_apps.jpg)
2、在对应包下新建`config.py`文件，需要包含以下内容：
```
app_name = "apps_other.app_test" # 应用名称，与新建的python包名保持一致并添加前缀apps_other.即可
celery_tasks = ("apps_other.test.celery_tasks",) # celery后台任务文件路径，如果不需要，可以不需要这个变量
add_middleware = ("apps_other.test.middleware.TestMiddleware",) # app自定义中间件，不需要可以不要这个变量
# 这里可以将app需要的其它变量配置到这里，注意变量命名须以 APP_ 开头
```
![config.py](./docs/img/config.png)

3、环境变量配置
如果开发过程中需要使用到环境变量，可以按照如下，选择一个.env文件添加
![config.py](./docs/img/env.png)
文件内容格式如下：
```
APP_ID=WEOPS
APP_TOKEN=123456
```

4、注意事项
开发过程中不要修改除apps_other目录外的其它文件
本地开发时，可以在根目录新建local_settings.py文件，并将database相关的配置信息写在里面
```
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "",  # noqa
        "USER": "",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "",
        # 单元测试 DB 配置，建议不改动
        "TEST": {"NAME": "test_db", "CHARSET": "utf8", "COLLATION": "utf8_general_ci"},
    },
}
```

# 快速入门

前置准备：
* 已经安装好蓝鲸智云的PaaS平台
* 在本地hosts文件加入如下配置: 127.0.0.1 dev.weops.com

在WeOps Framework框架中完成API开发：

1、新建文件夹`apps_other`/`app_test`
2、新建`config.py`
```
app_name = "apps_other.app_test"
```
3、新建`urls.py`
```
from rest_framework.routers import DefaultRouter
from . import views

router = DefaultRouter()
router.register(r'', views.HelloViewSet, "hello")

urlpatterns = router.urls
```

4、新建`views.py`
```
from rest_framework.routers import DefaultRouter

from apps_other.app_test import views

router = DefaultRouter()
router.register(r'', views.HelloViewSet, "hello")

urlpatterns = router.urls
```

5、在根目录下新建`local_settings.py`
```
APP_ID="<SaaS的APP ID>"
APP_TOKEN="<SaaS的Token>"
RUN_VER="open"
BK_URL="<蓝鲸PaaS平台的地址>"
BK_PAAS_HOST="<蓝鲸PaaS平台的地址>"
BK_PAAS_INNER_HOST="<蓝鲸PaaS平台的地址>"

BROKER_URL='<RabbitMQ的地址>'

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.mysql",
        "NAME": "",  # noqa
        "USER": "root",
        "PASSWORD": "",
        "HOST": "",
        "PORT": "3306",
        # 单元测试 DB 配置，建议不改动
        "TEST": {"NAME": "test_db", "CHARSET": "utf8", "COLLATION": "utf8_general_ci"},
    },
}
```
6、访问`http://dev.weops.com:8000/docs/` 就可以看到刚才加入的API了