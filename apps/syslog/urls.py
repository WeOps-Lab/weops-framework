from django.conf.urls import url
from rest_framework.routers import SimpleRouter

from apps.syslog.views.config_views import SidecarCollectorsConfigViews
from apps.syslog.views.index import IndexViewSet
from apps.syslog.views.log import SyslogViewSet
from apps.syslog.views.probe import ProbeViewSet, job_call_back
from apps.syslog.views.stream import StreamViewSet

urlpatterns = (url(r"^job_call_back/$", job_call_back),)

router = SimpleRouter()

router.register(r"", SyslogViewSet, basename="syslog")
router.register(r"probe", ProbeViewSet, basename="syslog-probe")
router.register(r"stream", StreamViewSet, basename="syslog-stream")
router.register(r"index", IndexViewSet, basename="syslog-index")

router.register(r"collectors_config", SidecarCollectorsConfigViews, basename="sidecar_collectors_config")

urlpatterns += tuple(router.urls)
