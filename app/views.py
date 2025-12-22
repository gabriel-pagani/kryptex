import json
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import user_passes_test
from django.http import JsonResponse, HttpResponseBadRequest
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
        .order_by("type__title", "-is_fav", "service")
    )

    if q:
        logins = logins.filter(
            Q(service__icontains=q)
            | Q(login__icontains=q)
            | Q(type__title__icontains=q)
            | Q(notes__icontains=q)
        )

    favorites = [item for item in logins if item.is_fav]

    groups_map = {}
    for item in logins:
        if item.type:
            key = f"type-{item.type.id}"
            title = item.type.title
        else:
            key = "none"
            title = "• • •"

        groups_map.setdefault(key, {"key": key, "title": title, "items": []})
        groups_map[key]["items"].append(item)

    groups = sorted(groups_map.values(), key=lambda g: g["title"].lower())



    total_count = sum(len(g["items"]) for g in groups)

    if favorites:
        groups.insert(0, {"key": "fav", "title": "Favoritos", "items": favorites})    

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
        "notes": login_item.notes,
        "is_fav": login_item.is_fav,
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

        new_item = Logins.objects.create(
            service=data["service"],
            login=data["login"],
            password=data["password"],
            notes=data.get("notes", ""),
            is_fav=data.get("is_fav", False),
            type=login_type
        )
        return JsonResponse({
            "status": "ok",
            "item": {
                "id": new_item.id,
                "service": new_item.service,
                "login": new_item.login,
                "notes": new_item.notes or "",
                "is_fav": bool(new_item.is_fav),
                "type_id": new_item.type.id if new_item.type else ""
            }
        })
    except Exception as e:
        return JsonResponse({"status": "error"}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def update_login_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    
    try:
        data = json.loads(request.body)
        
        # Atualiza campos básicos
        login_item.service = data.get("service", login_item.service)
        login_item.login = data.get("login", login_item.login)
        login_item.notes = data.get("notes", login_item.notes)
        
        # Atualiza favorito
        if "is_fav" in data:
            login_item.is_fav = bool(data["is_fav"])

        # Atualiza senha apenas se enviada
        if "password" in data and data["password"]:
            login_item.password = data["password"]

        # Atualiza tipo
        if "type_id" in data:
            if data["type_id"]:
                login_item.type = LoginTypes.objects.filter(pk=data["type_id"]).first()
            else:
                login_item.type = None

        login_item.save()
        return JsonResponse({
            "status": "ok",
            "item": {
                "id": login_item.id,
                "service": login_item.service,
                "login": login_item.login,
                "notes": login_item.notes or "",
                "is_fav": bool(login_item.is_fav),
                "type_id": login_item.type.id if login_item.type else ""
            }
        })
    except Exception as e:
        return JsonResponse({"status": "error"}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def delete_login_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    try:
        login_item.delete()
        return JsonResponse({"status": "ok"})
    except Exception as e:
        return JsonResponse({"status": "error"}, status=500)


@require_POST
@user_passes_test(lambda u: u.is_active and u.is_staff)
def get_password_api(request, login_id):
    login_item = get_object_or_404(Logins, pk=login_id)
    return JsonResponse({"password": login_item.password})
