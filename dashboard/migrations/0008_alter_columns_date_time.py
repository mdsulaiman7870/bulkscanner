# Generated by Django 4.1.1 on 2022-10-03 12:08

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0007_alter_columns_date_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='columns',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 3, 17, 8, 19, 478762)),
        ),
    ]