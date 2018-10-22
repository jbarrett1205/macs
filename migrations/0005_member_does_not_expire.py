# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('macs', '0004_auto_20180730_1344'),
    ]

    operations = [
        migrations.AlterField(
            model_name='member',
            name='expires',
            field=models.DateField(null=True, blank=True),
        ),
    ]
