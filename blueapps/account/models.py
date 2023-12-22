from __future__ import unicode_literals

from django.contrib.auth.base_user import BaseUserManager
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.core import validators
from django.db import models
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _


class UserManager(BaseUserManager):
    def _create_user(self, username, is_staff=False, is_superuser=False, password=None, **extra_fields):
        now = timezone.now()
        if not username:
            raise ValueError(_("The given username must be set"))
        user = self.model(
            username=username,
            is_active=True,
            is_staff=is_staff,
            is_superuser=is_superuser,
            date_joined=now,
            **extra_fields
        )
        if password:
            user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, password=None, **extra_fields):
        return self._create_user(username, False, False, password, **extra_fields)

    def create_superuser(self, username, password=None, **extra_fields):
        return self._create_user(username, True, True, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin):
    username = models.CharField(
        _("username"),
        max_length=64,
        unique=True,
        help_text=_("Required. 64 characters or fewer. Letters, " "digits and underlined only."),
        validators=[
            validators.RegexValidator(
                r"^[a-zA-Z0-9_]+$",
                _(
                    "Enter a valid openid. "
                    "This value may contain only letters, "
                    "numbers and underlined characters."
                ),
                "invalid",
            ),
        ],
        error_messages={"unique": _("A user with that openid already exists.")},
    )

    nickname = models.CharField(
        _("nick name"), max_length=64, blank=True, help_text=_("Required. 64 characters or fewer."),
    )
    is_staff = models.BooleanField(
        _("staff status"), default=False, help_text=_("Designates whether the user can log into this " "admin site."),
    )
    is_active = models.BooleanField(
        _("active"),
        default=True,
        help_text=_(
            "Designates whether this user should be treated as " "active. Unselect this instead of deleting accounts."
        ),
    )
    date_joined = models.DateTimeField(_("date joined"), default=timezone.now,)

    objects = UserManager()

    USERNAME_FIELD = "username"
    REQUIRED_FIELDS = ["nickname"]

    class Meta:
        verbose_name = _("user")
        verbose_name_plural = _("users")
