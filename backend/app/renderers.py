from rest_framework.renderers import BrowsableAPIRenderer, JSONRenderer

class StaffBrowsableAPIRenderer(BrowsableAPIRenderer):
    def render(self, data, accepted_media_type=None, renderer_context=None):
        request = renderer_context.get('request') if renderer_context else None
        user = getattr(request, 'user', None)

        if user and user.is_staff:
            return super().render(data, accepted_media_type, renderer_context)
        return JSONRenderer().render(data, accepted_media_type, renderer_context)
