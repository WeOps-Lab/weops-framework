import os

app_name = "apps.system_mgmt"
celery_tasks = ("apps.system_mgmt.celery_tasks",)
# add_middleware = (
#     "apps.system_mgmt.middleware.ApplicationMenusPermission",
#     "apps.system_mgmt.casbin_package.casbin_middleware.CasbinRBACMiddleware",
# )

# 以下是casbin配置

CASBIN_MESH_PORT = os.getenv("BKAPP_CASBIN_MESH_PORT", "4002")
CASBIN_MESH_HOST = os.getenv("BKAPP_CASBIN_MESH_HOST", "casbin-mesh-container")
OPSPLIOT_URL = os.getenv("BKAPP_OPSPLIOT_URL", "opspliot.serivce.consul")
OPSPLIOT_SOCKET_PATH = os.getenv("BKAPP_OPSPLIOT_SOCKET_PATH", "/socket.io/")
OPSPLIOT_JS_URL = os.getenv("BKAPP_OPSPLIOT_JS_URL", "/index.js")
