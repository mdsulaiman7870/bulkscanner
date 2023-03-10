# Generated by Django 4.1.1 on 2022-10-06 09:30

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('virustotal', '0013_alter_all_ips_date_time_alter_hashes_date_time_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='hashes',
            old_name='sign_info',
            new_name='signature_info',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='copyright',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='description',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='file_version',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='harmless_votes',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='malicious_votes',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='original_name',
        ),
        migrations.RemoveField(
            model_name='hashes',
            name='type_description',
        ),
        migrations.AlterField(
            model_name='all_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 6, 14, 30, 2, 489074)),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 6, 14, 30, 2, 490735)),
        ),
        migrations.AlterField(
            model_name='hashes',
            name='meaningful_name',
            field=models.JSONField(null=True),
        ),
        migrations.AlterField(
            model_name='malicious_ips',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 10, 6, 14, 30, 2, 490113)),
        ),
    ]
