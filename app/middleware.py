class SecurityHeadersMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        resp = self.get_response(request)

        resp["Content-Security-Policy"] = (
            "default-src 'none'; "
            "base-uri 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "object-src 'none'; "
            "frame-src 'none'; "
            "worker-src 'none'; "
            "media-src 'none'; "
            "manifest-src 'self'; "
            "img-src 'self' data:; "
            "font-src 'self' data:; "
            "style-src 'self'; "
            "script-src 'self'; "
            "connect-src 'self'; "
            "script-src-attr 'none'; "
            "upgrade-insecure-requests; "
            "block-all-mixed-content"
        )

        resp["X-Content-Type-Options"] = "nosniff"
        resp["Referrer-Policy"] = "same-origin"
        resp["Cross-Origin-Opener-Policy"] = "same-origin"
        resp["Cross-Origin-Resource-Policy"] = "same-origin"
        resp["Permissions-Policy"] = "clipboard-write=(self)"

        return resp