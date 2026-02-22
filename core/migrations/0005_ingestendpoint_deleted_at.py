from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("beacon", "0004_alter_channel_type"),
    ]

    operations = [
        migrations.AddField(
            model_name="ingestendpoint",
            name="deleted_at",
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
