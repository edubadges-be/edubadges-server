# Generated by Django 2.2.14 on 2021-03-29 13:19

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('directaward', '0004_remove_directaward_recipient'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='directaward',
            name='acceptance',
        ),
    ]
