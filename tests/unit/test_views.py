from http import HTTPStatus
from unittest.mock import MagicMock

from fastapi.testclient import TestClient

from src.auth.dto import (
    CreateOrganizationPayload, 
    CreateUserPayload, 
    UserResponse,
    UserResponseFlat,
    OrganizationResponse,
)
from src.auth.services import OrganizationService, UserService
from src.auth.views import get_organization_service, get_user_service
from src.main import app


def get_user_service_mock():
    def create_user_method_mock(
        payload: CreateUserPayload, 
        organzation_service: OrganizationService
    ):
        return UserResponse(
            id="d8719698-eb36-45d7-a630-0cdd56346457",
            email=payload.email,
            username=payload.username,
            owned_organization=None,
            organization=None,
        )

    user_service_mock = MagicMock()
    user_service_mock.create_user = create_user_method_mock
    return user_service_mock


def get_organization_service_mock():
    def create_organization_method_mock(
        payload: CreateOrganizationPayload, 
        user_service: UserService
    ):
        return OrganizationResponse(
            id="72cfe120-6d39-4f8b-8c29-609b690361ef",
            name="test_org",
            owner=UserResponseFlat(
                id=payload.owner_id,
                email="owner@test.com",
                username="owner",
            ),
            members=[
                UserResponseFlat(
                    id=payload.member_ids[0],
                    email="test_1@test.com",
                    username="test_1",
                ),
                UserResponseFlat(
                    id=payload.member_ids[1],
                    email="test_2@test.com",
                    username="test_2",
                ),
            ]
        )

    organization_service_mock = MagicMock()
    organization_service_mock.create_organization = create_organization_method_mock
    return organization_service_mock


def test_user_create():
    app.dependency_overrides[get_user_service] = get_user_service_mock

    client = TestClient(app)
    payload = {"email": "test@test.com", "username": "test", "password": "not_hashed"}

    response = client.post("/auth/users", json=payload)

    assert response.status_code == HTTPStatus.OK
    assert response.json().get("id") 
    assert response.json().get("email") == payload["email"]
    assert response.json().get("username") == payload["username"]


def test_organization_create():
    app.dependency_overrides[get_organization_service] = get_organization_service_mock

    client = TestClient(app)
    payload = {
        "name": "test_org",
        "owner_id": "d8719698-eb36-45d7-a630-0cdd56346457",
        "member_ids": [
            "e9819698-eb36-45d7-a630-0cdd56346457", 
            "f0919698-eb36-45d7-a630-0cdd56346457",
        ] 
    }

    response = client.post("/auth/organizations", json=payload)

    assert response.status_code == HTTPStatus.OK
    assert response.json().get("id")
    owner = response.json().get("owner")
    assert owner.get("id") == payload["owner_id"]
    assert owner.get("email") == "owner@test.com"
    assert owner.get("username") == "owner"
    member_1 = response.json().get("members")[0]
    assert member_1.get("id") == payload["member_ids"][0]
    assert member_1.get("email") == "test_1@test.com"
    assert member_1.get("username") == "test_1"
    member_2 = response.json().get("members")[1]
    assert member_2.get("id") == payload["member_ids"][1]
    assert member_2.get("email") == "test_2@test.com"
    assert member_2.get("username") == "test_2"
