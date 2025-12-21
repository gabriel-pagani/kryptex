import json
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse, HttpResponseForbidden, HttpResponseBadRequest
from django.views.decorators.http import require_POST
from django.db.models import Q
from .models import Logins, LoginTypes


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
    
    all_types = LoginTypes.objects.all()

    return render(
        request,
        "index.html",
        {"groups": groups, "q": q, "total_count": total_count, "all_types": all_types},
    )


@user_passes_test(lambda u: u.is_active and u.is_staff)
def get_login_details_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    return JsonResponse({
        "id": login_item.id,
        "service": login_item.service,
        "login": login_item.login,
        "password": login_item.password, # Retorna o blob cifrado
        "notes": login_item.notes,
        "type_id": login_item.type.id if login_item.type else ""
    })


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def create_login_api(request):
    try:
        data = json.loads(request.body)
        
        if not all(k in data for k in ("service", "login", "password")):
            return HttpResponseBadRequest("Dados incompletos")

        login_type = None
        if data.get("type_id"):
            login_type = LoginTypes.objects.filter(pk=data["type_id"]).first()

        Logins.objects.create(
            service=data["service"],
            login=data["login"],
            password=data["password"],
            notes=data.get("notes", ""),
            type=login_type
        )
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def update_login_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    
    try:
        data = json.loads(request.body)
        
        # Atualiza campos básicos
        login_item.service = data.get("service", login_item.service)
        login_item.login = data.get("login", login_item.login)
        login_item.notes = data.get("notes", "")
        
        # Atualiza senha apenas se enviada (já cifrada pelo frontend)
        if "password" in data and data["password"]:
            login_item.password = data["password"]

        # Atualiza tipo
        if "type_id" in data:
            if data["type_id"]:
                login_item.type = LoginTypes.objects.filter(pk=data["type_id"]).first()
            else:
                login_item.type = None

        login_item.save()
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def delete_login_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    try:
        login_item.delete()
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "error", "message": str(e)}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def get_password_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    return JsonResponse({"password": login_item.password})
