# Generated by Django 4.2.1 on 2023-12-15 23:21

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pet_shop', '0012_userprofile_verification_token_created_at'),
    ]

    operations = [
        migrations.AlterField(
            model_name='userprofile',
            name='two_factor_enabled',
            field=models.BooleanField(default=True),
        ),
    ]
