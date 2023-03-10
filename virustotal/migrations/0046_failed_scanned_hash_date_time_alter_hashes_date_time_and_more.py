# Generated by Django 4.1.1 on 2023-02-02 12:11

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0045_alter_hashes_date_time_alter_ip_addresses_date_time'),
    ]

    operations = [
        migrations.AddField(
            model_name='failed_scanned_hash',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2023, 2, 2, 17, 11, 35, 519621)),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2023, 2, 2, 17, 11, 35, 518579)),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2023, 2, 2, 17, 11, 35, 518579)),
        ),
    ]
