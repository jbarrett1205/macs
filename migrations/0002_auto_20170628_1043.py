# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models
import django.contrib.auth.models


class Migration(migrations.Migration):

    dependencies = [
        ('macs', '0001_initial'),
    ]

    operations = [
        migrations.AlterModelOptions(
            name='activitylog',
            options={'ordering': ('-timestamp',)},
        ),
        migrations.AlterModelManagers(
            name='member',
            managers=[
                ('objects', django.contrib.auth.models.UserManager()),
            ],
        ),
        migrations.AddField(
            model_name='resource',
            name='admin_url',
            field=models.URLField(help_text=b'URL for performing admin activity on the resource', blank=True),
        ),
        migrations.AlterField(
            model_name='keycard',
            name='comment',
            field=models.CharField(help_text=b'optional comment', max_length=128, blank=True),
        ),
    ]
