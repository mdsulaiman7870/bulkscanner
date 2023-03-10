# Generated by Django 4.1.1 on 2022-09-30 18:44

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0006_alter_all_ips_date_time_alter_hashes_date_time_and_more'),
    ]

    operations = [
        migrations.AlterField(
            model_name='all_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 30, 23, 44, 18, 8787)),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 30, 23, 44, 18, 8787)),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='type_description',
            field=models.CharField(max_length=100, null=True),
        ),
        migrations.AlterField(
            model_name='malicious_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 9, 30, 23, 44, 18, 8787)),
        ),
    ]
