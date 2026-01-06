from http import HTTPStatus
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import joinedload

from src.auth.exceptions import AuthenticationFailedException
from src.auth.models import Organization
from src.auth.repositories import OrganizationRepository, UserRepository
from src.auth.services import JWTService
from src.auth.views import OrganizationService, UserService
from src.main import app


class TestSignIn:
    def test_success(self, test_user_service, test_user_repository, test_user):
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        form_data = {"username": test_user.email, "password": "pass"}  # we use email as username
        response = client.post("/auth/token", data=form_data)
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.OK
        assert JWTService().decode_jwt(response_json["access_token"])["sub"] == test_user.email

    def test_wrong_pass(self, test_user_service, test_user_repository, test_user):
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        form_data = {"username": test_user.email, "password": "badbad"}
        response = client.post("/auth/token", data=form_data)
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response_json["detail"] == AuthenticationFailedException.detail

    def test_user_nonexistant(self, test_user_service, test_user_repository, test_user):
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        form_data = {"username": "bad@bad.bad", "password": "badbad"}
        response = client.post("/auth/token", data=form_data)
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response_json["detail"] == AuthenticationFailedException.detail


class TestUserCreate:
    def test_user_create_success(self, test_user_service, test_user_repository):
        password = "pass"
        password_hashed = JWTService().hash_password(password)
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        payload = {"email": "test@test.com", "username": "test", "password": password}
        response = client.post("/auth/users", json=payload)
        response_json = response.json()

        user_count = test_user_repository.get_count()
        users = test_user_repository.get_all()

        assert response.status_code == HTTPStatus.OK
        assert user_count == 1
        assert str(users[0].id) == response.json()["id"]
        assert users[0].email == payload["email"] == response_json["email"]
        assert users[0].username == payload["username"] == response_json["username"]
        assert users[0].password_hash == password_hashed

    @pytest.mark.parametrize(
        "email, username, expected_error",
        [
            (
                "test_user@test.com", 
                "test_user", 
                "The following fields contain non-unique values: ['username', 'email']",
            ),
            (
                "test_user@test.com", 
                "unique_username", 
                "The following field contains non-unique value: ['email']",
            ),
            (
                "unique_email@test.com", 
                "test_user", 
                "The following field contains non-unique value: ['username']",
            ),

        ]
    )
    def test_user_create_duplicate_fields(
        self, 
        test_user_service, 
        test_user_repository, 
        test_user,
        email,
        username,
        expected_error
    ):
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        payload = {"email": email, "username": username, "password": "pass"}
        response = client.post("/auth/users", json=payload)
        response_json = response.json()

        user_count = test_user_repository.get_count()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
        assert user_count == 1
        assert response_json["detail"] == expected_error


@pytest.mark.skip(reason="cleaning up the codebase")
def test_organization_create(
    test_organization_service, 
    test_organization_repository,
    test_user_service, 
    test_users,
):
    app.dependency_overrides[OrganizationService] = lambda: test_organization_service
    app.dependency_overrides[UserService] = lambda: test_user_service
    client = TestClient(app)

    owner = test_users[0]
    member = test_users[1]

    payload = {"name": "test_org", "owner_id": str(owner.id), "member_ids": [str(member.id)]}
    response = client.post("/auth/organizations", json=payload)
    response_json = response.json()

    organization_count = test_organization_repository.get_count()
    organization_id = test_organization_repository.get_all()[0].id
    organization = test_organization_repository.get_by_id(
        str(organization_id), 
        relationships=[joinedload(Organization.owner), joinedload(Organization.members)],
    )

    assert response.status_code == HTTPStatus.OK
    assert organization_count == 1
    assert str(organization.id) == response_json["id"]
    assert organization.name == payload["name"] == response_json["name"]
    assert str(organization.owner.id) == payload["owner_id"] == response_json["owner"]["id"]
    assert organization.owner.email == owner.email == response_json["owner"]["email"]
    assert organization.owner.username == owner.username == response_json["owner"]["username"]
    assert (
        [str(member.id) for member in organization.members] 
        == [member["id"] for member in response_json["members"]]
    )
    assert (
        [member.email for member in organization.members] 
        == [member["email"] for member in response_json["members"]]
    )
    assert (
        [member.username for member in organization.members] 
        == [member["username"] for member in response_json["members"]]
    )


@pytest.mark.skip(reason="cleaning up the codebase")
def test_organization_list(
    test_organization_service, 
    test_organization_repository, 
    test_user_service,
    test_organization,
):
    app.dependency_overrides[OrganizationService] = lambda: test_organization_service
    app.dependency_overrides[UserService] = lambda: test_user_service

    client = TestClient(app)
    response = client.get("/auth/organizations")
    response_json = response.json()
