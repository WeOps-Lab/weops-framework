# -- coding: utf-8 --
# @File: decorators.py
# @Time: 2023/11/14 14:03
# @Author: windyzhao

from functools import wraps


def required_exempt(view_func):
    """Mark a view function as being exempt from the CSRF view protection."""

    # view_func.csrf_exempt = True would also work, but decorators are nicer
    # if they don't have side effects, so return a new function.
    def wrapped_view(*args, **kwargs):
        return view_func(*args, **kwargs)

    wrapped_view.csrf_exempt = True
    wrapped_view.login_exempt = True
    return wraps(view_func)(wrapped_view)
