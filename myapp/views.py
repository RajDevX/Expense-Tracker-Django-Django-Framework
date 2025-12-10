from datetime import date, timedelta
from urllib.parse import urlencode

from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.mail import send_mail
from django.core.paginator import Paginator
from django.db.models import Q, Sum
from django.shortcuts import redirect, render
from django.urls import reverse
from django.utils import timezone
from django.utils.crypto import get_random_string

from .models import Expence, Income, User

EXPENSE_CATEGORY_LABELS = {
    "food": "Food & Dining",
    "rent": "Rent",
    "travel": "Travel",
    "fees": "Fees",
    "entertainment": "Entertainment",
    "utilities": "Utilities",
    "others": "Others",
}

INCOME_CATEGORY_LABELS = {
    "salary": "Salary",
    "bonus": "Bonus",
    "interest": "Interest",
    "rental": "Rental Income",
    "investments": "Investments",
    "others": "Others",
}


def signup(req):
    return render(req, "signup.html")


def login(req):
    success_message = req.session.pop("feedback_message", "")
    context = {}
    if success_message:
        context["success"] = success_message
    return render(req, "login.html", context)


def _build_financial_context(uid: int) -> dict:
    user = User.objects.filter(id=uid).first()
    if not user:
        return {}

    today = timezone.localdate()
    start_of_month = date(today.year, today.month, 1)
    current_month_label = today.strftime("%B %Y")

    expense_queryset = Expence.objects.filter(user_id=uid)
    income_queryset = Income.objects.filter(user_id=uid)

    monthly_expense = (
        expense_queryset.filter(date__range=(start_of_month, today)).aggregate(
            total=Sum("amount")
        )["total"]
        or 0
    )
    monthly_income = (
        income_queryset.filter(date__range=(start_of_month, today)).aggregate(
            total=Sum("amount")
        )["total"]
        or 0
    )
    total_expense = expense_queryset.aggregate(total=Sum("amount"))["total"] or 0
    total_income = income_queryset.aggregate(total=Sum("amount"))["total"] or 0

    remaining_budget = (user.monthly_budget or 0) - monthly_expense
    budget_usage = 0
    if user.monthly_budget:
        budget_usage = min(
            100, round((monthly_expense / user.monthly_budget) * 100, 2)
        )
    monthly_balance = round(monthly_income - monthly_expense, 2)

    expense_breakdown_qs = (
        expense_queryset.filter(date__range=(start_of_month, today))
        .values("category")
        .annotate(total=Sum("amount"))
    )
    expense_category_breakdown = sorted(
        [
            {
                "label": EXPENSE_CATEGORY_LABELS.get(
                    row["category"],
                    (row["category"] or "Uncategorised").replace("_", " ").title(),
                ),
                "value": round(row["total"] or 0, 2),
            }
            for row in expense_breakdown_qs
            if row["total"]
        ],
        key=lambda item: item["value"],
        reverse=True,
    )

    income_breakdown_qs = (
        income_queryset.filter(date__range=(start_of_month, today))
        .values("category")
        .annotate(total=Sum("amount"))
    )
    income_category_breakdown = sorted(
        [
            {
                "label": INCOME_CATEGORY_LABELS.get(
                    row["category"],
                    (row["category"] or "Uncategorised").replace("_", " ").title(),
                ),
                "value": round(row["total"] or 0, 2),
            }
            for row in income_breakdown_qs
            if row["total"]
        ],
        key=lambda item: item["value"],
        reverse=True,
    )

    income_vs_expense_values = []
    if monthly_income or monthly_expense:
        income_vs_expense_values = [
            {"label": "Income", "value": round(monthly_income, 2)},
            {"label": "Expense", "value": round(monthly_expense, 2)},
        ]

    savings_rate = 0
    expense_to_income_ratio = 0
    if monthly_income:
        savings_rate = round((monthly_balance / monthly_income) * 100, 2)
        expense_to_income_ratio = round((monthly_expense / monthly_income) * 100, 2)
    net_total = round(total_income - total_expense, 2)
    savings_rate_clamped = min(100, max(0, savings_rate))

    budget_alert = None
    if user.monthly_budget:
        threshold_ratio = monthly_expense / user.monthly_budget if user.monthly_budget else 0
        if threshold_ratio >= 1:
            budget_alert = {
                "status": "danger",
                "message": (
                    f"You have reached your monthly budget of Rs {user.monthly_budget:.2f}. "
                    "Consider reviewing recent expenses to stay on track."
                ),
            }
        elif threshold_ratio >= 0.9:
            budget_alert = {
                "status": "warning",
                "message": (
                    f"You have used {round(threshold_ratio * 100, 1)}% of your monthly budget "
                    f"({monthly_expense:.2f} of {user.monthly_budget:.2f})."
                ),
            }

    return {
        "user_profile": user,
        "monthly_expense": round(monthly_expense, 2),
        "monthly_income": round(monthly_income, 2),
        "total_expense": round(total_expense, 2),
        "total_income": round(total_income, 2),
        "remaining_budget": round(remaining_budget, 2),
        "monthly_balance": monthly_balance,
        "budget_usage": budget_usage,
        "savings_rate": savings_rate,
        "savings_rate_clamped": savings_rate_clamped,
        "expense_to_income_ratio": expense_to_income_ratio,
        "net_total": net_total,
        "top_expense_category": expense_category_breakdown[0] if expense_category_breakdown else None,
        "top_income_category": income_category_breakdown[0] if income_category_breakdown else None,
        "current_month_label": current_month_label,
        "expense_category_breakdown": expense_category_breakdown,
        "income_category_breakdown": income_category_breakdown,
        "income_vs_expense_values": income_vs_expense_values,
        "budget_alert": budget_alert,
    }


def _require_login(req):
    if "uid" not in req.session:
        return redirect("/login")
    return None


def _require_admin(req):
    if "admin_id" not in req.session:
        req.session["admin_feedback_message"] = "Please sign in to manage user accounts."
        return redirect("/admin-login")
    return None


def _get_income_for_user(income_id: int, uid: int) -> Income | None:
    return Income.objects.filter(id=income_id, user_id=uid).first()


def _get_expense_for_user(expense_id: int, uid: int) -> Expence | None:
    return Expence.objects.filter(id=expense_id, user_id=uid).first()


def _issue_reset_token(user: User) -> str:
    token = get_random_string(48)
    user.reset_token = token
    user.reset_token_created = timezone.now()
    user.save(update_fields=["reset_token", "reset_token_created"])
    return token


def _token_is_valid(user: User) -> bool:
    if not user.reset_token or not user.reset_token_created:
        return False
    token_age = timezone.now() - user.reset_token_created
    ttl = getattr(settings, "PASSWORD_RESET_TOKEN_TTL_MINUTES", 30)
    return token_age <= timedelta(minutes=ttl)


def _send_password_reset_email(
    user: User, request, initiated_by_admin: bool = False
) -> str:
    token = _issue_reset_token(user)
    reset_url = request.build_absolute_uri(
        reverse("password_reset_confirm", args=[token])
    )
    ttl = getattr(settings, "PASSWORD_RESET_TOKEN_TTL_MINUTES", 30)
    if initiated_by_admin:
        reason = (
            "An administrator has requested a password reset for your account. "
            "If you made this request, use the link below to set a new password."
        )
    else:
        reason = (
            "You recently requested to reset your Daily Expense Manager password. "
            "Use the link below to choose a new password."
        )
    message = (
        f"Hi {user.uname},\n\n"
        f"{reason}\n\n"
        f"{reset_url}\n\n"
        f"This link will expire in {ttl} minutes.\n"
        "If you did not request a password reset, no action is required.\n\n"
        "Thank you,\nDaily Expense Manager"
    )
    send_mail(
        "Reset your Daily Expense Manager password",
        message,
        settings.DEFAULT_FROM_EMAIL,
        [user.email],
    )
    return token


def dashbord(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    uid = req.session["uid"]
    user = User.objects.get(id=uid)
    status_message = ""

    if req.method == "POST":
        try:
            raw_budget = (req.POST.get("monthly_budget") or "").strip()
            budget_value = float(raw_budget or 0)
            if budget_value < 0:
                raise ValueError("Budget must be positive.")
            user.monthly_budget = budget_value
            user.save(update_fields=["monthly_budget"])
            status_message = "Monthly budget updated successfully."
        except ValueError:
            status_message = "Please enter a valid budget amount."

    context = _build_financial_context(uid)
    context.update(
        {
            "status_message": status_message,
            "recent_expenses": Expence.objects.filter(user_id=uid)
            .order_by("-date", "-time")[:5],
            "recent_incomes": Income.objects.filter(user_id=uid)
            .order_by("-date", "-time")[:5],
        }
    )
    profile_feedback = req.session.pop("profile_feedback", None)
    if profile_feedback:
        context["profile_feedback"] = profile_feedback
    profile_form_values = req.session.pop("profile_form_values", None)
    if profile_form_values:
        context["profile_form_values"] = profile_form_values

    return render(req, "dashbord.html", context)


def Addexpence(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    context = _build_financial_context(req.session["uid"])
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    profile_feedback = req.session.pop("profile_feedback", None)
    if profile_feedback:
        context["profile_feedback"] = profile_feedback
    profile_form_values = req.session.pop("profile_form_values", None)
    if profile_form_values:
        context["profile_form_values"] = profile_form_values
    return render(req, "expenceadd.html", context)


def Addincome(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    context = _build_financial_context(req.session["uid"])
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    profile_feedback = req.session.pop("profile_feedback", None)
    if profile_feedback:
        context["profile_feedback"] = profile_feedback
    profile_form_values = req.session.pop("profile_form_values", None)
    if profile_form_values:
        context["profile_form_values"] = profile_form_values
    return render(req, "incomeadd.html", context)


def signupsave(req):
    if req.method != "POST":
        return redirect("/")

    uname = (req.POST.get("uname") or "").strip()
    email = (req.POST.get("email") or "").strip().lower()
    password = req.POST.get("upass") or ""
    mobile = (req.POST.get("umobile") or "").strip()
    address = (req.POST.get("uaddress") or "").strip()
    age_raw = req.POST.get("age")

    context = {
        "form_values": {
            "uname": uname,
            "email": email,
            "mobile": mobile,
            "address": address,
            "age": age_raw,
        }
    }

    if not uname or not email or not password or not mobile or not address:
        context["error"] = "All fields are required. Please review your details."
        return render(req, "signup.html", context)

    try:
        age = int(age_raw)
    except (TypeError, ValueError):
        context["error"] = "Please provide a valid age."
        return render(req, "signup.html", context)

    if User.objects.filter(uname=uname).exists():
        context["error"] = "This username is already taken. Please choose another."
        return render(req, "signup.html", context)

    if User.objects.filter(email=email).exists():
        context["error"] = "We already have an account with this email address."
        return render(req, "signup.html", context)

    user = User(
        uname=uname,
        email=email,
        age=age,
        upassword=make_password(password),
        mobile=mobile,
        address=address,
    )
    user.save()
    req.session["feedback_message"] = (
        "Account created successfully. Please sign in with your credentials."
    )
    return redirect("/login")


def loginsave(req):
    uname = req.POST.get("unm")
    upassword = req.POST.get("pwd")
    if not uname or not upassword:
        error = "Please provide both username and password."
        return render(req, "login.html", {"Error": error})

    user = User.objects.filter(uname=uname).first()
    if user and check_password(upassword, user.upassword):
        if not user.is_active:
            error = "Your account is currently disabled. Contact the administrator."
            return render(req, "login.html", {"Error": error})
        req.session["uid"] = user.id
        req.session["uname"] = user.uname
        return redirect("/home")
    error = "Invalid username or password. Please try again."
    return render(req, "login.html", {"Error": error})


def forgot_password(req):
    # Implementation updated in password reset flow below.
    return redirect("/password-reset")


def admin_login(req):
    context = {}
    notice = req.session.pop("admin_status_message", "")
    if notice:
        context["status"] = notice

    if req.method == "POST":
        uname = (req.POST.get("unm") or "").strip()
        password = req.POST.get("pwd") or ""
        admin_user = User.objects.filter(uname=uname, is_admin=True).first()
        if admin_user and check_password(password, admin_user.upassword):
            if not admin_user.is_active:
                context["error"] = "This administrator account is disabled."
                return render(req, "admin_login.html", context)
            req.session["admin_id"] = admin_user.id
            req.session["admin_name"] = admin_user.uname
            return redirect("/admin/dashboard")
        context["error"] = "Invalid administrator credentials."
    return render(req, "admin_login.html", context)


def admin_dashboard(req):
    redirect_response = _require_admin(req)
    if redirect_response:
        return redirect_response

    def _filter_non_admin_users(queryset, search_query, status_filter, email_filter):
        filtered = queryset
        if search_query:
            filtered = filtered.filter(
                Q(uname__icontains=search_query)
                | Q(email__icontains=search_query)
                | Q(mobile__icontains=search_query)
            )
        if status_filter == "active":
            filtered = filtered.filter(is_active=True)
        elif status_filter == "inactive":
            filtered = filtered.filter(is_active=False)

        if email_filter == "with":
            filtered = filtered.exclude(email__isnull=True).exclude(email="")
        elif email_filter == "without":
            filtered = filtered.filter(Q(email__isnull=True) | Q(email=""))
        return filtered

    base_users = User.objects.filter(is_admin=False)

    if req.method == "POST":
        action = (req.POST.get("bulk_action") or "").strip().lower()
        selected_ids = req.POST.getlist("selected_users")
        select_all_scope = (req.POST.get("select_all_scope") or "").lower() == "all"
        redirect_params = {}
        for param in ("q", "status", "email", "page"):
            value = (req.POST.get(param) or "").strip()
            if value:
                redirect_params[param] = value
        redirect_query = urlencode(redirect_params)
        redirect_url = "/admin/dashboard"
        if redirect_query:
            redirect_url = f"{redirect_url}?{redirect_query}"

        if not selected_ids and not select_all_scope:
            req.session["admin_status_message"] = (
                "Select at least one user before running a bulk action."
            )
            return redirect(redirect_url)

        if action not in {"activate", "deactivate"}:
            req.session["admin_status_message"] = "Choose a valid bulk action to continue."
            return redirect(redirect_url)

        search_query = (req.POST.get("q") or "").strip()
        status_filter = (req.POST.get("status") or "").strip().lower()
        email_filter = (req.POST.get("email") or "").strip().lower()

        filtered_users = _filter_non_admin_users(base_users, search_query, status_filter, email_filter)

        if select_all_scope:
            selected_ids = list(filtered_users.values_list("id", flat=True))

        users_to_update = filtered_users.filter(id__in=selected_ids)
        if not users_to_update.exists():
            req.session["admin_status_message"] = (
                "No matching users were found for the selected action."
            )
            return redirect(redirect_url)

        desired_state = action == "activate"
        updated_count = users_to_update.exclude(is_active=desired_state).update(
            is_active=desired_state
        )
        if updated_count:
            state_label = "activated" if desired_state else "deactivated"
            req.session["admin_status_message"] = (
                f"{updated_count} user{'s' if updated_count != 1 else ''} {state_label}."
            )
        else:
            req.session["admin_status_message"] = (
                "The selected users already had that status."
            )
        return redirect(redirect_url)

    message = req.session.pop("admin_status_message", "")

    search_query = (req.GET.get("q") or "").strip()
    status_filter = (req.GET.get("status") or "").strip().lower()
    email_filter = (req.GET.get("email") or "").strip().lower()

    filtered_users = _filter_non_admin_users(base_users, search_query, status_filter, email_filter)
    ordered_users = filtered_users.order_by("uname").only(
        "id", "uname", "email", "mobile", "is_active", "reset_token_created"
    )
    paginator = Paginator(ordered_users, 5)
    page_number = req.GET.get("page")
    page_obj = paginator.get_page(page_number)
    users = page_obj.object_list

    filtered_count = filtered_users.count()

    query_params = req.GET.copy()
    if "page" in query_params:
        query_params.pop("page")
    preserved_query = query_params.urlencode()

    context = {
        "admin_name": req.session.get("admin_name", "Administrator"),
        "users": users,
        "page_obj": page_obj,
        "preserved_query": preserved_query,
        "search_query": search_query,
        "status_filter": status_filter,
        "email_filter": email_filter,
        "metrics": {
            "total": base_users.count(),
            "active": base_users.filter(is_active=True).count(),
            "inactive": base_users.filter(is_active=False).count(),
            "with_email": base_users.exclude(email__isnull=True)
            .exclude(email="")
            .count(),
            "filtered": filtered_count,
        },
    }
    if message:
        context["status"] = message
    return render(req, "admin_dashboard.html", context)


def admin_toggle_user(req, user_id: int):
    redirect_response = _require_admin(req)
    if redirect_response:
        return redirect_response

    if req.method != "POST":
        return redirect("/admin/dashboard")

    user = User.objects.filter(id=user_id, is_admin=False).first()
    if not user:
        req.session["admin_status_message"] = "Unable to find the requested user."
        return redirect("/admin/dashboard")

    user.is_active = not user.is_active
    user.save(update_fields=["is_active"])
    state = "activated" if user.is_active else "deactivated"
    req.session["admin_status_message"] = f"User {user.uname} has been {state}."
    return redirect("/admin/dashboard")


def admin_send_reset_link(req, user_id: int):
    redirect_response = _require_admin(req)
    if redirect_response:
        return redirect_response

    if req.method != "POST":
        return redirect("/admin/dashboard")

    user = User.objects.filter(id=user_id, is_admin=False).first()
    if not user:
        req.session["admin_status_message"] = "Unable to find the requested user."
        return redirect("/admin/dashboard")

    if not user.email:
        req.session["admin_status_message"] = (
            f"User {user.uname} does not have an email address on file."
        )
        return redirect("/admin/dashboard")

    _send_password_reset_email(user, req, initiated_by_admin=True)
    req.session["admin_status_message"] = (
        f"A reset link has been emailed to {user.email}."
    )
    return redirect("/admin/dashboard")


def admin_logout(req):
    req.session.pop("admin_id", None)
    req.session.pop("admin_name", None)
    req.session["admin_status_message"] = "You have been signed out."
    return redirect("/admin-login")


def profile_update(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    next_url = req.POST.get("next") or req.META.get("HTTP_REFERER") or "/home"

    user = User.objects.filter(id=req.session.get("uid")).first()
    if not user:
        req.session["profile_feedback"] = {
            "status": "error",
            "message": "Unable to find your user account.",
            "show_modal": True,
        }
        return redirect(next_url)

    if req.method != "POST":
        return redirect(next_url)

    form_email = (req.POST.get("email") or "").strip().lower()
    form_mobile = (req.POST.get("mobile") or "").strip()
    form_address = (req.POST.get("address") or "").strip()
    form_budget = (req.POST.get("monthly_budget") or "").strip()

    submitted_values = {
        "email": form_email,
        "mobile": form_mobile,
        "address": form_address,
        "monthly_budget": form_budget,
    }

    errors = []
    if form_email and User.objects.filter(email=form_email).exclude(id=user.id).exists():
        errors.append("That email address is already in use.")
    if form_mobile and not form_mobile.isdigit():
        errors.append("Mobile number should contain digits only.")

    budget_value = None
    if form_budget:
        try:
            budget_value = float(form_budget)
            if budget_value < 0:
                errors.append("Monthly budget must be zero or positive.")
        except ValueError:
            errors.append("Please enter a valid number for monthly budget.")

    if errors:
        req.session["profile_feedback"] = {
            "status": "error",
            "message": errors[0],
            "show_modal": True,
        }
        req.session["profile_form_values"] = submitted_values
        return redirect(next_url)

    update_fields = []
    if user.email != form_email:
        user.email = form_email or None
        update_fields.append("email")
    if user.mobile != form_mobile:
        user.mobile = form_mobile
        update_fields.append("mobile")
    if user.address != form_address:
        user.address = form_address
        update_fields.append("address")
    if budget_value is not None and user.monthly_budget != budget_value:
        user.monthly_budget = budget_value
        update_fields.append("monthly_budget")

    if update_fields:
        user.save(update_fields=update_fields)
        req.session["profile_feedback"] = {
            "status": "success",
            "message": "Profile updated successfully.",
            "show_modal": False,
        }
    else:
        req.session["profile_feedback"] = {
            "status": "info",
            "message": "No changes detected in your profile.",
            "show_modal": False,
        }

    req.session.pop("profile_form_values", None)
    return redirect(next_url)


def reset_financial_snapshot(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    next_url = req.POST.get("next") or req.META.get("HTTP_REFERER") or "/home"
    if req.method != "POST":
        return redirect(next_url)

    uid = req.session.get("uid")
    user = User.objects.filter(id=uid).first()
    Income.objects.filter(user_id=uid).delete()
    Expence.objects.filter(user_id=uid).delete()
    if user:
        user.monthly_budget = 0
        user.save(update_fields=["monthly_budget"])

    req.session["profile_feedback"] = {
        "status": "success",
        "message": "Your financial overview has been reset.",
        "show_modal": False,
    }
    req.session.pop("profile_form_values", None)
    return redirect(next_url)


def password_reset_request(req):
    context = {}
    if req.method == "POST":
        email = (req.POST.get("email") or "").strip().lower()
        context["form_values"] = {"email": email}
        if not email:
            context["error"] = "Please enter the email address associated with your account."
        else:
            user = User.objects.filter(email=email).first()
            if user and user.is_active:
                _send_password_reset_email(user, req)
            context.pop("form_values", None)
            context["success"] = (
                "If an account exists for that email address, a reset link has been sent."
            )
    return render(req, "password_reset_request.html", context)


def password_reset_confirm(req, token: str):
    user = User.objects.filter(reset_token=token).first()
    if not user or not _token_is_valid(user):
        return render(
            req,
            "password_reset_confirm.html",
            {"invalid": True},
        )

    context = {"token": token, "email": user.email}
    if req.method == "POST":
        password = req.POST.get("password") or ""
        confirm_password = req.POST.get("confirm_password") or ""
        if not password or not confirm_password:
            context["error"] = "Please provide and confirm your new password."
        elif password != confirm_password:
            context["error"] = "The passwords do not match. Please try again."
        elif len(password) < 8:
            context["error"] = "Please choose a password with at least 8 characters."
        else:
            user.upassword = make_password(password)
            user.reset_token = None
            user.reset_token_created = None
            user.save(update_fields=["upassword", "reset_token", "reset_token_created"])
            req.session["feedback_message"] = (
                "Your password has been reset successfully. Please sign in."
            )
            return redirect("/login")
    return render(req, "password_reset_confirm.html", context)


def ExpenceSAve(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    if req.method != "POST":
        return redirect("/Addexpence")

    uid = req.session["uid"]
    obj = Expence()
    obj.time = req.POST.get("time")
    obj.date = req.POST.get("date")
    obj.remark = req.POST.get("remark")
    obj.amount = req.POST.get("amount")
    obj.category = req.POST.get("category")
    obj.user_id = uid
    obj.save()
    req.session["page_notice"] = "Expense saved successfully."
    req.session["page_notice_level"] = "success"
    return redirect("/Addexpence")


def edit_expense(req, expense_id: int):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    uid = req.session["uid"]
    expense = _get_expense_for_user(expense_id, uid)
    if not expense:
        req.session["page_notice"] = "We couldn't find that expense entry."
        req.session["page_notice_level"] = "warning"
        return redirect("/Allexpence")

    if req.method == "POST":
        date_value = req.POST.get("date")
        time_value = req.POST.get("time")
        remark = (req.POST.get("remark") or "").strip()
        amount = req.POST.get("amount")
        category = req.POST.get("category")

        if not (date_value and time_value and remark and amount and category):
            context = _build_financial_context(uid)
            context.update(
                {
                    "expense": expense,
                    "is_edit": True,
                    "form_action": reverse("edit_expense", args=[expense_id]),
                    "form_error": "Please fill in all fields before saving.",
                }
            )
            return render(req, "expenceadd.html", context)

        expense.date = date_value
        expense.time = time_value
        expense.remark = remark
        expense.amount = amount
        expense.category = category
        expense.save()
        req.session["page_notice"] = "Expense updated successfully."
        req.session["page_notice_level"] = "success"
        return redirect("/Allexpence")

    context = _build_financial_context(uid)
    context.update(
        {
            "expense": expense,
            "is_edit": True,
            "form_action": reverse("edit_expense", args=[expense_id]),
        }
    )
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    return render(req, "expenceadd.html", context)


def IncomeSAve(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    if req.method != "POST":
        return redirect("/Addincome")

    uid = req.session["uid"]
    obj = Income()
    obj.time = req.POST.get("time")
    obj.date = req.POST.get("date")
    obj.remark = req.POST.get("remark")
    obj.amount = req.POST.get("amount")
    obj.category = req.POST.get("category")
    obj.user_id = uid
    obj.save()
    req.session["page_notice"] = "Income saved successfully."
    req.session["page_notice_level"] = "success"
    return redirect("/Addincome")


def edit_income(req, income_id: int):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    uid = req.session["uid"]
    income = _get_income_for_user(income_id, uid)
    if not income:
        req.session["page_notice"] = "We couldn't find that income entry."
        req.session["page_notice_level"] = "warning"
        return redirect("/AllInCome")

    if req.method == "POST":
        date_value = req.POST.get("date")
        time_value = req.POST.get("time")
        remark = (req.POST.get("remark") or "").strip()
        amount = req.POST.get("amount")
        category = req.POST.get("category")

        if not (date_value and time_value and remark and amount and category):
            context = _build_financial_context(uid)
            context.update(
                {
                    "income": income,
                    "is_edit": True,
                    "form_action": reverse("edit_income", args=[income_id]),
                    "form_error": "Please fill in all fields before saving.",
                }
            )
            return render(req, "incomeadd.html", context)

        income.date = date_value
        income.time = time_value
        income.remark = remark
        income.amount = amount
        income.category = category
        income.save()
        req.session["page_notice"] = "Income updated successfully."
        req.session["page_notice_level"] = "success"
        return redirect("/AllInCome")

    context = _build_financial_context(uid)
    context.update(
        {
            "income": income,
            "is_edit": True,
            "form_action": reverse("edit_income", args=[income_id]),
        }
    )
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    return render(req, "incomeadd.html", context)


def AllIncome(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    uid = req.session["uid"]
    context = _build_financial_context(uid)
    context["data"] = Income.objects.filter(user_id=uid).order_by("-date", "-time")
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    profile_feedback = req.session.pop("profile_feedback", None)
    if profile_feedback:
        context["profile_feedback"] = profile_feedback
    profile_form_values = req.session.pop("profile_form_values", None)
    if profile_form_values:
        context["profile_form_values"] = profile_form_values
    return render(req, "allincome.html", context)


def Allexpence(req):
    redirect_response = _require_login(req)
    if redirect_response:
        return redirect_response

    uid = req.session["uid"]
    context = _build_financial_context(uid)
    context["data"] = Expence.objects.filter(user_id=uid).order_by("-date", "-time")
    notice = req.session.pop("page_notice", "")
    if notice:
        context["page_notice"] = notice
        level = req.session.pop("page_notice_level", "")
        if level:
            context["page_notice_level"] = level
    else:
        req.session.pop("page_notice_level", None)
    profile_feedback = req.session.pop("profile_feedback", None)
    if profile_feedback:
        context["profile_feedback"] = profile_feedback
    profile_form_values = req.session.pop("profile_form_values", None)
    if profile_form_values:
        context["profile_form_values"] = profile_form_values
    return render(req, "allexpence.html", context)


def logout(req):
    req.session.pop("uid", None)
    req.session.pop("uname", None)
    req.session["feedback_message"] = "You have been logged out safely."
    return redirect("/login")
