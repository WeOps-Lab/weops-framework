# Generated by Django 2.2.6 on 2023-06-05 14:52

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("system_mgmt", "0017_menumanage"),
    ]

    operations = [
        migrations.AddField(
            model_name="sysuser",
            name="status",
            field=models.CharField(
                choices=[("NORMAL", "正常"), ("DISABLED", "禁用")], default="NORMAL", max_length=32, verbose_name="用户状态"
            ),
        ),
    ]
