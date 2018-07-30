# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('macs', '0002_auto_20170628_1043'),
    ]

    operations = [
        migrations.AddField(
            model_name='member',
            name='incognito',
            field=models.BooleanField(default=False),
        ),
    ]
