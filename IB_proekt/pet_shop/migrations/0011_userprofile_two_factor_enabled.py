# Generated by Django 4.2.1 on 2023-12-15 11:54

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pet_shop', '0010_remove_userprofile_salt'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='two_factor_enabled',
            field=models.BooleanField(default=False),
        ),
    ]
