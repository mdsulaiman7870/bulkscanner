# Generated by Django 4.1.1 on 2022-10-08 07:05

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0029_failed_scanned_ip_alter_all_ips_date_time_and_more'),
    ]

    operations = [
        migrations.DeleteModel(
            name='all_ips',
        ),
        migrations.DeleteModel(
            name='malicious_ips',
        ),
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 8, 12, 5, 7, 578708)),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 8, 12, 5, 7, 577710)),
        ),
    ]
