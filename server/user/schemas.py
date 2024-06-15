from ninja import Schema
from pydantic import EmailStr, constr
from ninja import ModelSchema
from django.contrib.auth import get_user_model

class RegistrationSchema(Schema):
    first_name: str
    last_name: str
    email: EmailStr
    password: str
    password2: str

class LoginSchema(Schema):
    email: EmailStr
    password: str


class UserSchema(ModelSchema):
    class Config:
        model = get_user_model()
        model_fields = ["id", "email", "is_staff", "first_name", "last_name"]
