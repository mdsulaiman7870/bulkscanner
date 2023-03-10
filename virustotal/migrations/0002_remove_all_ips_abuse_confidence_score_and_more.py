# Generated by Django 4.1.1 on 2022-09-22 09:16

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0001_initial'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='all_ips',
            name='abuse_confidence_Score',
        ),
        migrations.RemoveField(
            model_name='all_ips',
            name='country',
        ),
        migrations.RemoveField(
            model_name='malicious_ips',
            name='abuse_confidence_Score',
        ),
        migrations.RemoveField(
            model_name='malicious_ips',
            name='country',
        ),
        migrations.AlterField(
            model_name='all_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 22, 14, 16, 43, 834414)),
        ),
        migrations.AlterField(
            model_name='malicious_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 22, 14, 16, 43, 834414)),
        ),
    ]
