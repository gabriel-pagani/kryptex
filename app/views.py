from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse, HttpResponseForbidden
from django.db.models import Q
from .models import Logins


@user_passes_test(lambda u: u.is_active and u.is_staff, login_url="/admin/login/")
def home_view(request):
    q = (request.GET.get("q") or "").strip()

    logins = (
        Logins.objects.select_related("type")
        .defer("password") 
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

@user_passes_test(lambda u: u.is_active and u.is_staff)
def get_password_api(request, login_id):
    if request.method != "POST":
        return HttpResponseForbidden()
    
    login_item = get_object_or_404(Logins, pk=login_id)
    return JsonResponse({"password": login_item.decrypted_password})
