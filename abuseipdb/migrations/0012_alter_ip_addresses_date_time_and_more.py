# Generated by Django 4.1.1 on 2023-01-22 13:36

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('abuseipdb', '0011_alter_ip_addresses_date_time'),
    ]

    operations = [
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2023, 1, 22, 18, 36, 30, 428355)),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='isPublic',
            field=models.CharField(max_length=10, null=True),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='isWhitelisted',
            field=models.BooleanField(null=True),
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='lastReportedAt',
            field=models.DateTimeField(null=True),
        ),
    ]