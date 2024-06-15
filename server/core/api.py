from ninja import NinjaAPI
from user.views import router as user_router


api = NinjaAPI()
api.add_router('auth/', user_router)
