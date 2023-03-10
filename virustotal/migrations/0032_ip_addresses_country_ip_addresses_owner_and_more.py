# Generated by Django 4.1.1 on 2022-10-08 07:16

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0031_alter_hashes_date_time_alter_ip_addresses_date_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='ip_addresses',
            name='country',
            field=models.JSONField(null=True),
        ),
        migrations.AddField(
            model_name='ip_addresses',
            name='owner',
            field=models.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 8, 12, 16, 8, 237403)),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 8, 12, 16, 8, 237403)),
        ),
    ]
