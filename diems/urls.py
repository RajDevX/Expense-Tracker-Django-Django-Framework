"""
URL configuration for diems project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.urls import path

from myapp import views as v1
from django.contrib import admin

urlpatterns = [
    path("django-admin/", admin.site.urls),
    path("", v1.signup),
    path("login", v1.login),
    path("signsave", v1.signupsave),
    path("loginsave", v1.loginsave),
    path("forgot-password", v1.forgot_password),
    path("password-reset", v1.password_reset_request, name="password_reset_request"),
    path(
        "password-reset/<str:token>",
        v1.password_reset_confirm,
        name="password_reset_confirm",
    ),
    path("admin-login", v1.admin_login, name="admin_login"),
    path("admin/dashboard", v1.admin_dashboard, name="admin_dashboard"),
    path("admin/logout", v1.admin_logout, name="admin_logout"),
    path(
        "admin/users/<int:user_id>/toggle",
        v1.admin_toggle_user,
        name="admin_toggle_user",
    ),
    path(
        "admin/users/<int:user_id>/send-reset",
        v1.admin_send_reset_link,
        name="admin_send_reset",
    ),
    path("profile/update", v1.profile_update, name="profile_update"),
    path("profile/reset-overview", v1.reset_financial_snapshot, name="reset_financial_snapshot"),
    path("home", v1.dashbord),
    path("Addexpence", v1.Addexpence),
    path("ExpenceSAve", v1.ExpenceSAve),
    path("Addincome", v1.Addincome),
    path("incomesave", v1.IncomeSAve),
    path("AllInCome", v1.AllIncome),
    path("Allexpence", v1.Allexpence),
    path("income/<int:income_id>/edit", v1.edit_income, name="edit_income"),
    path("expense/<int:expense_id>/edit", v1.edit_expense, name="edit_expense"),
    path("logout", v1.logout),
]
