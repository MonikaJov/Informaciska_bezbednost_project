# Generated by Django 4.2.1 on 2023-12-14 23:15

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('pet_shop', '0008_alter_userprofile_verification_token'),
    ]

    operations = [
        migrations.AddField(
            model_name='userprofile',
            name='salt',
            field=models.CharField(default=0, max_length=255),
            preserve_default=False,
        ),
    ]
