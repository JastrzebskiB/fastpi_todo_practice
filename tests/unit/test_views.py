from http import HTTPStatus
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from src.auth.dto import CreateUserPayload
from src.auth.models import User
from src.auth.views import get_user_service
from src.main import app


def get_user_service_mock():
    def create_user_method_mock(payload: CreateUserPayload):
        return User(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email=payload.email,
            username=payload.username,
            password_hash="hashed",
        )

    create_user_service_mock = MagicMock()
    create_user_service_mock.create_user = create_user_method_mock
    return create_user_service_mock


app.dependency_overrides[get_user_service] = get_user_service_mock


def test_user_create():
    client = TestClient(app)
    service = MagicMock(app)
    payload = {"email": "test@test.com", "username": "test", "password": "not_hashed"}

    response = client.post("/auth/users", json=payload)

    assert response.status_code == HTTPStatus.OK
    assert response.json().get("id") 
    assert response.json().get("email") == payload["email"]
    assert response.json().get("username") == payload["username"]
