# Generated by Django 4.1.1 on 2022-09-22 08:03

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0003_columns'),
    ]

    operations = [
        migrations.AlterField(
            model_name='columns',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 22, 13, 3, 40, 535273)),
        ),
    ]