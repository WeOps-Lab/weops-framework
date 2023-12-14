"""
性能测试
"""

import logging
import time
from functools import partial, wraps

log = logging.getLogger("performance")


def fn_performance(
    func=None,
    log=log,
    threshold=1,
    stack_info=False,
    level=logging.ERROR,
    notify="",
    message="[fn: {fn_name}] [func: {func}] [timer: {time}]",
    show_param=True,
):
    if func is None:
        return partial(
            fn_performance,
            log=log,
            level=level,
            message=message,
            notify=notify,
            threshold=threshold,
            stack_info=stack_info,
            show_param=show_param,
        )

    @wraps(func)
    def wrapper(*real_args, **real_kwargs):
        t0 = time.time()

        result = func(*real_args, **real_kwargs)

        interval = round(time.time() - t0, 5)

        nonlocal log
        nonlocal threshold

        if interval >= threshold:
            if show_param:
                msg = """The [func_name: {fn_name}] [func: {func}]
[args:{realfn_args}]
[kwargs: {realfn_kwargs}]
[timer:{time}s] [threshold:{threshold}s], please timely optimize.
""".format(
                    fn_name=func.__name__,
                    func=func,
                    time=interval,
                    realfn_args=real_args,
                    realfn_kwargs=real_kwargs,
                    threshold=threshold,
                )
                from common.bk_api_utils.main import ApiDefine

                if isinstance(real_args[0], ApiDefine):
                    msg += f"[url: {real_args[0].total_url}]\n"
                log.log(
                    logging.WARNING, msg, stack_info=stack_info,
                )

            else:
                log.log(
                    logging.WARNING,
                    "The [func_name: {fn_name}] [func: {func}] \n\r"
                    "[timer:{time}s] [threshold:{threshold}s], please timely optimize.\n".format(
                        fn_name=func.__name__, func=func, time=interval, threshold=threshold
                    ),
                    stack_info=stack_info,
                )
        return result

    return wrapper
