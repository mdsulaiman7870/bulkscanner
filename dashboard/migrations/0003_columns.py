# Generated by Django 4.1.1 on 2022-09-22 07:04

import datetime
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('dashboard', '0002_abuseipdb_apis'),
    ]

    operations = [
        migrations.CreateModel(
            name='columns',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('column_name', models.CharField(max_length=150, unique=True)),
                ('date_time', models.DateTimeField(default=datetime.datetime(2022, 9, 22, 12, 4, 3, 964423))),
            ],
        ),
    ]
