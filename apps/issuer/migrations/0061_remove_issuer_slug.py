# Generated by Django 2.2.9 on 2020-03-02 19:11

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('issuer', '0060_issuer_staff'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='issuer',
            name='slug',
        ),
    ]
