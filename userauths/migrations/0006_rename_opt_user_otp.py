# Generated by Django 4.2 on 2024-05-24 13:16

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ("userauths", "0005_user_opt"),
    ]

    operations = [
        migrations.RenameField(
            model_name="user",
            old_name="opt",
            new_name="otp",
        ),
    ]
