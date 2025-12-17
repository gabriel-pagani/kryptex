migrate:
	@python manage.py makemigrations && python manage.py migrate

runserver:
ifeq ($(ssl),true)
	@python manage.py runserver_plus --cert-file cert.crt
else
	@python manage.py runserver
endif

createsuperuser:
	@python manage.py shell -c "from django.contrib.auth.models import User; User.objects.filter(username='admin').exists() or User.objects.create_superuser(username='admin', password='1234')"
