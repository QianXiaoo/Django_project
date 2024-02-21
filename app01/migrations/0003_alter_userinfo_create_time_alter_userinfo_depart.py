# Generated by Django 5.0.2 on 2024-02-17 08:13

import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("app01", "0002_remove_userinfo_did"),
    ]

    operations = [
        migrations.AlterField(
            model_name="userinfo",
            name="create_time",
            field=models.DateField(verbose_name="入职时间"),
        ),
        migrations.AlterField(
            model_name="userinfo",
            name="depart",
            field=models.ForeignKey(
                on_delete=django.db.models.deletion.CASCADE,
                to="app01.department",
                verbose_name="部门",
            ),
        ),
    ]