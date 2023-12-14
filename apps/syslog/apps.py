from django.apps import AppConfig
from django.db.models.signals import post_migrate
from django.utils.translation import ugettext_lazy as _

from utils.app_log import logger


class SyslogConfig(AppConfig):
    name = "apps.syslog"
    verbose_name = _("syslog")

    def ready(self):
        try:
            from apps.syslog.utils.migrate_notice import init_migrate_notice

            post_migrate.connect(init_migrate_notice, sender=self)
        except Exception as e:
            logger.exception(getattr(e, "message", e))

        try:
            from apps.syslog.utils.migrate_notice import init_syslog

            post_migrate.connect(init_syslog, sender=self)
        except Exception as e:
            logger.exception(getattr(e, "message", e))

        try:
            from apps.syslog.utils.migrate_event_definition import init_syslog_event_definitions

            post_migrate.connect(init_syslog_event_definitions, sender=self)
        except Exception as e:
            logger.exception(getattr(e, "message", e))

        try:
            from apps.syslog.utils.migrate_streams import init_streams

            post_migrate.connect(init_streams, sender=self)
        except Exception as e:
            logger.exception(getattr(e, "message", e))

        try:
            from apps.syslog.utils.migrate_input import init_local_log_input

            post_migrate.connect(init_local_log_input, sender=self)
        except Exception as e:
            logger.exception(getattr(e, "message", e))
