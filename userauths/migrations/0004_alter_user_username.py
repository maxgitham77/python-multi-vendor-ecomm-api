# Generated by Django 4.2 on 2024-05-24 10:55

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("userauths", "0003_alter_user_options_alter_user_managers_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="user",
            name="username",
            field=models.CharField(blank=True, max_length=255, null=True),
        ),
    ]
