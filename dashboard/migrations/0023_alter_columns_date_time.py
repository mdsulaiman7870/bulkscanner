# Generated by Django 4.1.1 on 2022-10-06 11:46

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0022_alter_columns_date_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='columns',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 6, 16, 46, 3, 517405)),
        ),
    ]