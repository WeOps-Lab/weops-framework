# Generated by Django 2.2.6 on 2021-11-23 15:32

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("system_mgmt", "0004_grademanager_usergroup"),
    ]

    operations = [
        migrations.AddField(
            model_name="grademanager",
            name="is_used",
            field=models.BooleanField(default=False, help_text="当前使用的版本"),
        ),
    ]
