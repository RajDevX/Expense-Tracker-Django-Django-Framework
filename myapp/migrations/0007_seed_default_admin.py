from django.contrib.auth.hashers import make_password
from django.db import migrations


def seed_default_admin(apps, schema_editor):
    User = apps.get_model("myapp", "User")

    if User.objects.filter(is_admin=True).exists():
        return

    User.objects.create(
        age=30,
        uname="admin",
        email="admin@example.com",
        upassword=make_password("Admin@123"),
        mobile="0000000000",
        address="Administrator",
        monthly_budget=0,
        is_admin=True,
        is_active=True,
    )


def remove_default_admin(apps, schema_editor):
    User = apps.get_model("myapp", "User")
    User.objects.filter(uname="admin", is_admin=True).delete()


class Migration(migrations.Migration):
    dependencies = [
        ("myapp", "0006_user_email_user_is_active_user_is_admin_and_more"),
    ]

    operations = [
        migrations.RunPython(seed_default_admin, remove_default_admin),
    ]
