# Generated by Django 4.1.1 on 2022-10-10 11:53

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0035_alter_hashes_date_time_alter_ip_addresses_date_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 10, 16, 53, 1, 512312)),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 10, 16, 53, 1, 512312)),
        ),
    ]
