from django.contrib.auth.hashers import make_password
from django.test import TestCase
from django.urls import reverse

from .models import User


class AdminLoginTests(TestCase):
    def setUp(self) -> None:
        self.password = "TestPass123!"
        self.admin = User.objects.create(
            age=30,
            uname="admin_user",
            email="admin@example.com",
            upassword=make_password(self.password),
            mobile="0123456789",
            address="Admin Street",
            monthly_budget=0,
            is_admin=True,
            is_active=True,
        )

    def test_admin_login_success(self):
        response = self.client.post(
            reverse("admin_login"), {"unm": self.admin.uname, "pwd": self.password}
        )

        self.assertEqual(response.status_code, 302)
        self.assertEqual(response.url, "/admin/dashboard")
        session = self.client.session
        self.assertEqual(session.get("admin_id"), self.admin.id)
        self.assertEqual(session.get("admin_name"), self.admin.uname)

    def test_admin_login_invalid_credentials(self):
        response = self.client.post(
            reverse("admin_login"), {"unm": self.admin.uname, "pwd": "wrongpass"}
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Invalid administrator credentials.")
        session = self.client.session
        self.assertIsNone(session.get("admin_id"))
        self.assertIsNone(session.get("admin_name"))

    def test_admin_login_disabled_account(self):
        self.admin.is_active = False
        self.admin.save(update_fields=["is_active"])

        response = self.client.post(
            reverse("admin_login"), {"unm": self.admin.uname, "pwd": self.password}
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "This administrator account is disabled.")
        session = self.client.session
        self.assertIsNone(session.get("admin_id"))
        self.assertIsNone(session.get("admin_name"))


class AdminDashboardBulkActionTests(TestCase):
    def setUp(self) -> None:
        self.admin_password = "AdminBulk123!"
        self.admin = User.objects.create(
            age=32,
            uname="bulk_admin",
            email="bulkadmin@example.com",
            upassword=make_password(self.admin_password),
            mobile="0123456788",
            address="Admin Avenue",
            monthly_budget=0,
            is_admin=True,
            is_active=True,
        )
        self.active_user = User.objects.create(
            age=24,
            uname="active_user",
            email="active@example.com",
            upassword=make_password("UserPass123!"),
            mobile="0123456787",
            address="Active Street",
            monthly_budget=0,
            is_admin=False,
            is_active=True,
        )
        self.inactive_user = User.objects.create(
            age=26,
            uname="inactive_user",
            email="inactive@example.com",
            upassword=make_password("InactivePass123!"),
            mobile="0123456786",
            address="Inactive Street",
            monthly_budget=0,
            is_admin=False,
            is_active=False,
        )
        session = self.client.session
        session["admin_id"] = self.admin.id
        session["admin_name"] = self.admin.uname
        session.save()

    def test_bulk_activate_updates_users(self):
        response = self.client.post(
            reverse("admin_dashboard"),
            {
                "bulk_action": "activate",
                "selected_users": [str(self.inactive_user.id)],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.inactive_user.refresh_from_db()
        self.assertTrue(self.inactive_user.is_active)

    def test_bulk_deactivate_updates_users(self):
        response = self.client.post(
            reverse("admin_dashboard"),
            {
                "bulk_action": "deactivate",
                "selected_users": [str(self.active_user.id)],
            },
        )

        self.assertEqual(response.status_code, 302)
        self.active_user.refresh_from_db()
        self.assertFalse(self.active_user.is_active)

    def test_bulk_action_requires_selection(self):
        response = self.client.post(
            reverse("admin_dashboard"),
            {"bulk_action": "activate"},
        )

        self.assertEqual(response.status_code, 302)
        session = self.client.session
        self.assertEqual(
            session.get("admin_status_message"),
            "Select at least one user before running a bulk action.",
        )
