# Generated by Django 4.2.1 on 2023-12-15 23:11

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pet_shop', '0011_userprofile_two_factor_enabled'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='verification_token_created_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
