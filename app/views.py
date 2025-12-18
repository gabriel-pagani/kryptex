from django.shortcuts import render
from django.contrib.auth.decorators import user_passes_test
from django.db.models import Q
from .models import Logins


@user_passes_test(lambda u: u.is_active and u.is_staff, login_url="/admin/login/")
def home_view(request):
    q = (request.GET.get("q") or "").strip()

    logins = (
        Logins.objects.select_related("type")
        .all()
        .order_by("service")
    )

    if q:
        logins = logins.filter(
            Q(service__icontains=q)
            | Q(login__icontains=q)
            | Q(type__title__icontains=q)
            | Q(notes__icontains=q)
        )

    return render(request, "index.html", {"logins": logins, "q": q})
