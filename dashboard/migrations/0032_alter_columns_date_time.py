# Generated by Django 4.1.1 on 2022-10-10 11:20

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0031_alter_columns_date_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='columns',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 10, 16, 20, 50, 438045)),
        ),
    ]