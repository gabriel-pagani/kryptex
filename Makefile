migrate:
	@python manage.py makemigrations && python manage.py migrate

runserver:
	@python manage.py runserver_plus --cert-file cert.crt

createsuperuser:
	@python manage.py shell -c "from django.contrib.auth.models import User; User.objects.filter(username='admin').exists() or User.objects.create_superuser(username='admin', password='1234')"
