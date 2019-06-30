# Generated by Django 2.2.2 on 2019-06-30 19:34

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("rest_framework_api_key", "0005_scopes"),
        ("heroes", "0002_prefix_hashed_key"),
    ]

    operations = [
        migrations.AddField(
            model_name="heroapikey",
            name="scopes",
            field=models.ManyToManyField(
                blank=True,
                help_text="Specific scopes for this API key",
                related_name="heroes_heroapikey_set",
                related_query_name="heroes_heroapikey",
                to="rest_framework_api_key.Scope",
                verbose_name="scopes",
            ),
        )
    ]
