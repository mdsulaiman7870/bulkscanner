# Generated by Django 4.1.1 on 2022-12-29 17:21

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('abuseipdb', '0006_stock_alter_ip_addresses_date_time'),
    ]

    operations = [
        migrations.DeleteModel(
            name='Stock',
        ),
        migrations.AlterField(
            model_name='ip_addresses',
            name='date_time',
            field=models.DateTimeField(default=datetime.datetime(2022, 12, 29, 22, 21, 10, 490789)),
        ),
    ]