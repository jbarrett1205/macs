# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('macs', '0003_member_incognito'),
    ]

    operations = [
        migrations.AddField(
            model_name='keycard',
            name='lockout_card',
            field=models.BooleanField(default=False, help_text=b'keycard is a lockout card'),
        ),
        migrations.AddField(
            model_name='resource',
            name='locked',
            field=models.BooleanField(default=False, help_text=b'resource is locked out'),
        ),
    ]
