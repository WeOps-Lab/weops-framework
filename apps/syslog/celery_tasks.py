from celery.schedules import crontab
from celery.task import periodic_task, task

from apps.syslog.services.probe import ProbeService
from blueapps.core.exceptions import BlueException
from utils.app_log import logger


@task()
def deal_job_result(job_id, job_code):
    """进行作业结果处理"""
    logger.info("进行作业结果处理！作业实例ID为：{}".format(job_id))
    try:
        ProbeService.callback(job_id, job_code)
    except BlueException as e:
        logger.exception(f"syslog callback, error: {e.message}")
    except Exception as e:
        logger.exception(e)


@periodic_task(run_every=crontab(minute="*/5", hour="*", day_of_month="*"))
def periodic_check_callback(expire_time=600):
    logger.info("每隔五分钟，定时检测运行600s以上的未完成任务！")
    try:
        ProbeService.check_not_callback_job(expire_time)
    except BlueException as e:
        logger.exception(f"periodic_check_callback, error: {e.message}")
    except Exception as e:
        logger.exception(e)
