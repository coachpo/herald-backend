from django.apps import AppConfig


class CoreConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'core'
    # Keep historical app label for migration/state compatibility.
    label = 'beacon'
