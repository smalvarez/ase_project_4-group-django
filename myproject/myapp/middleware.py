from django.utils.deprecation import MiddlewareMixin
import jwt
from django.conf import settings
from django.http import JsonResponse

class JWTAuthenticationMiddleware(MiddlewareMixin):
    def process_request(self, request):
        token = request.headers.get('Authorization')
        if token:
            try:
                decoded = jwt.decode(token.split(' ')[1], settings.SECRET_KEY, algorithms=['HS256'])
                request.user_email = decoded['email']
            except jwt.ExpiredSignatureError:
                return JsonResponse({'message': 'Token has expired.'}, status=401)
            except jwt.InvalidTokenError:
                return JsonResponse({'message': 'Invalid token.'}, status=403)
        return None
