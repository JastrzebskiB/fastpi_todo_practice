from datetime import datetime, timedelta
from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import joinedload

from src.auth.exceptions import AuthenticationFailedException
from src.auth.models import Organization
from src.auth.repositories import OrganizationRepository, UserRepository
from src.auth.services import JWTService
from src.auth.views import OrganizationService, UserService
from src.main import app

from tests.integration.conftest import create_test_organization


# Helpers
def generate_jwt(email) -> str:
    return JWTService.create_jwt({"sub": email}).access_token

def generate_auth_headers(email) -> dict:
    return {"Authorization": f"Bearer {generate_jwt(email)}"}


def hash_password(password) -> str:
    return JWTService.hash_password(password)


# Tests
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
    def test_success(self, test_user_service, test_user_repository):
        password = "pass"
        password_hashed = hash_password(password)
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
    def test_duplicate_fields(
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

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert user_count == 1
        assert response_json["detail"] == expected_error


class TestGetCurrentUser:
    def test_success(self, test_user_service, test_user_repository, test_user):
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.get("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["id"] == str(test_user.id)
        assert response_json["email"] == test_user.email
        assert response_json["username"] == test_user.username

    def test_invalid_token(self, test_user_service, test_user_repository):
        token = "bad.token"
        headers = {"Authorization": f"Bearer {token}"}
        
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.get("/auth/me", headers=headers)
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response_json["detail"] == "Could not validate credentials"

    # Not sure if this can happen IRL tbh, even patching this was a bit hard :D
    @patch("src.auth.services.JWTService")
    def test_token_encodes_no_mail(
        self, 
        jwt_service_patched,
        test_user_service, 
        test_user_repository,
        test_user
    ):
        jwt_service_patched.decode_jwt = lambda x: {}
        
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.get("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert response_json["detail"] == "JWT malformed or missing"

    def test_user_not_found(self,  test_user_service,  test_user_repository, test_user):
        test_user_repository.check_email_exists = lambda x: False
        
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.get("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()

        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response_json["detail"] == "User not found"


class TestDeleteUser:
    def test_success(self, test_user_service, test_user_repository, test_user): 
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.delete("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()
        user_count = test_user_repository.get_count()
    
        assert response.status_code == HTTPStatus.OK
        assert user_count == 0
        assert response_json["detail"] == "Successfully deleted user"

    @patch("src.auth.services.JWTService")
    def test_token_encodes_no_mail(
        self, 
        jwt_service_patched,
        test_user_service, 
        test_user_repository,
        test_user
    ):
        jwt_service_patched.decode_jwt = lambda x: {}
        
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.delete("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()
        user_count = test_user_repository.get_count()

        assert response.status_code == HTTPStatus.UNAUTHORIZED
        assert user_count == 1
        assert response_json["detail"] == "JWT malformed or missing"

    def test_user_not_found(self, test_user_service, test_user_repository, test_user):
        test_user_repository.check_email_exists = lambda x: False
        
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
        response = client.delete("/auth/me", headers=generate_auth_headers(test_user.email))
        response_json = response.json()

        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response_json["detail"] == "User not found"


class TestOrganizationCreate:
    def test_success(
        self,
        test_organization_service, 
        test_organization_repository,
        test_user_service,
        test_user_repository,
        test_users,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        owner = test_users[0]
        member = test_users[1]
        payload = {"name": "test_org", "member_ids": [str(member.id)]}
        response = client.post(
            "/auth/organizations", 
            headers=generate_auth_headers(owner.email), 
            json=payload,
        )
        response_json = response.json()
    
        organization_count = test_organization_repository.get_count()
        organization = test_organization_repository.get_all_organizations()[0]
    
        assert response.status_code == HTTPStatus.OK
        assert organization_count == 1
        assert str(organization.id) == response_json["id"]
        assert organization.name == payload["name"] == response_json["name"]
        assert str(organization.owner.id) == str(owner.id) == response_json["owner"]["id"]
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

    def test_duplicate_name(
        self,
        test_organization_service, 
        test_organization_repository,
        test_user_service,
        test_user_repository,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        payload = {"name": test_organization.name, "member_ids": [],}
        response = client.post(
            "/auth/organizations", 
            headers=generate_auth_headers(test_organization.owner.email), 
            json=payload,
        )        
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert test_organization_repository.get_count() == 1
        assert response_json["detail"] == "The following field contains non-unique value: ['name']"

    def test_missing_owner(
        self,
        test_organization_service, 
        test_organization_repository,
        test_user_service,
        test_user_repository,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        owner_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        member_id = "fe17ebee-453d-461d-981e-0a75237069a6"
        payload = {"name": "test_org", "member_ids": [member_id]}
        response = client.post(
            "/auth/organizations", 
            headers=generate_auth_headers("bad@mail.com"), 
            json=payload,
        )
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.NOT_FOUND
        assert test_organization_repository.get_count() == 0
        assert response_json["detail"] == (f"User not found")

    def test_missing_members(
        self,
        test_organization_service, 
        test_organization_repository,
        test_user_service,
        test_user_repository,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)
    
        member_ids = [
            "e6358d05-f648-4bc4-a251-08b087c801e8", "fe17ebee-453d-461d-981e-0a75237069a6"
        ]
        payload = {"name": "test_org", "member_ids": member_ids}
        response = client.post(
            "/auth/organizations", 
            headers=generate_auth_headers(test_user.email), 
            json=payload,
        )
        response_json = response.json()
    
        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert test_organization_repository.get_count() == 0
        assert response_json["detail"] == f"Users with the following ids: {member_ids} not found"


class TestOrganizationList:
    def test_success(
        self,
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

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 1
        assert response_json[0]["id"] == str(test_organization.id)
        assert response_json[0]["name"] == test_organization.name
        assert "owner" not in response_json[0]
        assert "members" not in response_json[0]


class TestOrganizationsMine:
    def test_success_owner(
        self,
        test_organization_service, 
        test_organization_repository, 
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
    
        client = TestClient(app)
        response = client.get(
            "/auth/me/organizations", 
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 1
        assert response_json[0]["id"] == str(test_organization.id)
        assert response_json[0]["name"] == test_organization.name
        assert "owner" in response_json[0]
        assert response_json[0]["owner"]["id"] == str(test_organization.owner_id) 
        assert "members" in response_json[0]
        assert len(response_json[0]["members"]) == 1

    def test_success_member(
        self,
        TestSession,
        test_organization_service, 
        test_organization_repository, 
        test_user_service,
        test_users,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service
    
        owner, member = test_users[0], test_users[1]
        organization = create_test_organization(
            TestSession,
            name="test_org",
            owner = owner,
            members=[member],
        )

        client = TestClient(app)
        response = client.get(
            "/auth/me/organizations", 
            headers=generate_auth_headers(member.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 1
        assert response_json[0]["id"] == str(organization.id)
        assert response_json[0]["name"] == organization.name
        assert "owner" in response_json[0]
        assert response_json[0]["owner"]["id"] == str(owner.id) 
        assert "members" in response_json[0]
        assert len(response_json[0]["members"]) == 2
    
    def test_success_owner_and_member(
        self,
        TestSession,
        test_organization_service, 
        test_organization_repository, 
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        test_organization_2 = create_test_organization(
            TestSession,
            name="test_org_2", 
            owner=test_user, 
            members=[test_organization.owner],
        )

        client = TestClient(app)
        response = client.get(
            "/auth/me/organizations", 
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 2
