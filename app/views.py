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
        .order_by("type__title", "service")
    )

    if q:
        logins = logins.filter(
            Q(service__icontains=q)
            | Q(login__icontains=q)
            | Q(type__title__icontains=q)
            | Q(notes__icontains=q)
        )

    groups_map = {}
    for item in logins:
        title = item.type.title if item.type else "• • •"
        groups_map.setdefault(title, []).append(item)

    groups = [{"title": title, "items": items} for title, items in sorted(groups_map.items(), key=lambda x: x[0].lower())]

    total_count = sum(len(g["items"]) for g in groups)

    return render(
        request,
        "index.html",
        {"groups": groups, "q": q, "total_count": total_count},
    )
