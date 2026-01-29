from datetime import datetime, timedelta
from http import HTTPStatus
from unittest.mock import MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import joinedload

from src.core.exceptions import AuthenticationFailedException
from src.auth.models import Organization
from src.auth.repositories import OrganizationRepository, UserRepository
from src.auth.services import JWTService
from src.auth.views import OrganizationAccessRequestService, OrganizationService, UserService
from src.todo import constants as todo_constants
from src.todo.dto import PartialUpdateColumnPayload
from src.todo.services import BoardService, ColumnService, TaskService
from src.main import app

from tests.integration.conftest import (
    create_test_board,
    create_test_column,
    create_test_organization_access_request, 
    create_test_organization,
    create_test_task,
) 


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


class TestAddOrRemoveMember:
    def test_add_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        payload = {"member_ids": [str(test_user.id)], "add": True}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 2
        assert str(test_user.id) in [user_json["id"] for user_json in response_json["members"]]

        # Confirm operation is idempotent
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 2
        assert str(test_user.id) in [user_json["id"] for user_json in response_json["members"]]

    def test_add_multiple_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_users,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_ids = [str(user.id) for user in test_users]
        payload = {"member_ids": member_ids, "add": True}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 3
        response_member_ids = [user_json["id"] for user_json in response_json["members"]]
        for member_id in member_ids:
            assert member_id in response_member_ids

    def test_add_fail_not_the_owner_of_the_org(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        payload = {"member_ids": [str(test_user.id)], "add": True}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_add_fail_organization_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        organization_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        payload = {"member_ids": [str(test_user.id)], "add": True}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{organization_id}/members",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_add_fail_user_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        payload = {"member_ids": [member_id], "add": True}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == f"User with the following id: ['{member_id}'] not found"

    def test_remove_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_id_to_remove = str(test_organization_with_members.members[0].id)
        payload = {"member_ids": [member_id_to_remove], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/members",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 2
        assert member_id_to_remove not in [
            user_json["id"] for user_json in response_json["members"]
        ]

        # Confirm operation is idempotent
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/members",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 2
        assert member_id_to_remove not in [
            user_json["id"] for user_json in response_json["members"]
        ]

    def test_remove_multiple_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_ids_to_remove = [
            str(test_organization_with_members.members[0].id),
            str(test_organization_with_members.members[1].id),
        ]
        payload = {"member_ids": member_ids_to_remove, "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/members",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json["members"]) == 1
        response_member_ids = [user_json["id"] for user_json in response_json["members"]]
        for member_id in member_ids_to_remove:
            assert member_id not in response_member_ids

    def test_remove_fail_not_the_owner_of_the_org(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        payload = {"member_ids": [str(test_user.id)], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_remove_fail_organization_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        organization_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        payload = {"member_ids": [str(test_user.id)], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{organization_id}/members",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_remove_fail_user_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        payload = {"member_ids": [member_id], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/members",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == f"User with the following id: ['{member_id}'] not found"

    # NOTE: we "fail silently" to keep with the idea of an idempotent operation
    def test_remove_user_not_a_member_of_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_id = str(test_user.id)
        payload = {"member_ids": [member_id], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/members",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert member_id not in [user_json["id"] for user_json in response_json["members"]]

    # NOTE: We disallow removing self as a member of the organization, there is another endpoint
    # for that
    def test_remove_user_not_a_member_of_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_id = str(test_organization_with_members.owner.id)
        payload = {"member_ids": [member_id], "add": False}
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/members",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert member_id in [user_json["id"] for user_json in response_json["members"]]


class TestLeaveOrganization:
    def test_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        member_mail = test_organization_with_members.members[0].email
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/leave",
            headers=generate_auth_headers(member_mail),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert member_mail not in [member["email"] for member in response_json["members"]]

    def test_fail_organization_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        organization_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{organization_id}/leave",
            headers=generate_auth_headers(test_user.email),
        )

        assert response.status_code == HTTPStatus.NOT_FOUND

    def test_not_a_member_of_the_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/leave",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert test_user.email not in [member["email"] for member in response_json["members"]]

    def test_owner_of_the_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/leave",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert str(test_organization.owner_id) in [
            member["id"] for member in response_json["members"]
        ]


class TestChangeOrganizationOwner:
    def test_success_change_owner_to_member_of_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        old_owner_id = str(test_organization_with_members.owner_id)
        new_owner = test_organization_with_members.members[0]
        new_owner_id = str(new_owner.id)
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/owner/{new_owner_id}",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["owner"]["id"] == new_owner_id
        response_member_ids = [user_json["id"] for user_json in response_json["members"]]
        assert old_owner_id in response_member_ids
        assert new_owner_id in response_member_ids

    def test_success_change_owner_to_user_outside_of_organization(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        old_owner_id = str(test_organization.owner_id)
        new_owner_id = str(test_user.id)
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/owner/{new_owner_id}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["owner"]["id"] == new_owner_id
        response_member_ids = [user_json["id"] for user_json in response_json["members"]]
        assert old_owner_id in response_member_ids
        assert new_owner_id in response_member_ids

    def test_fail_organization_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_users,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        organization_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{organization_id}/owner/{str(test_users[1].id)}",
            headers=generate_auth_headers(test_users[0].email),
        )

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_fail_new_owner_doesnt_exist(
        self,
        test_organization_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        new_owner_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/{str(test_organization.id)}/owner/{new_owner_id}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            f"User with the following id: ['{new_owner_id}'] not found"
        )


class TestOrganizationDelete:
    def test_success(
        self,
        test_organization_service,
        test_user_service,
        test_organization_repository,
        test_organization,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.delete(
            f"/auth/me/organizations/{str(test_organization.id)}/",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        count = test_organization_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == "Organization deleted successfully"
        assert count == 0

    def test_fail_organization_has_members(
        self,
        test_organization_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.delete(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/",
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            "Cannot delete an organization that still has other members"
        )

    def test_fail_organization_doesnt_exist(
        self, 
        test_organization_service, 
        test_user_service,
        test_user,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        organization_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        client = TestClient(app)
        response = client.delete(
            f"/auth/me/organizations/{organization_id}/",
            headers=generate_auth_headers(test_user.email),
        )

        assert response.status_code == HTTPStatus.FORBIDDEN

    def test_fail_not_an_owner_of_organization(
        self, 
        test_organization_service, 
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.delete(
            f"/auth/me/organizations/{str(test_organization_with_members.id)}/",
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN


class TestOrganizationAccessRequestCreate:
    def test_success(
        self,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization_access_request_repository,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        client = TestClient(app)
        response = client.post(
            f"/auth/organizations/{str(test_organization.id)}/request_access",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()
        count = test_organization_access_request_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["requester_id"] == str(test_user.id)
        assert response_json["organization_id"] == str(test_organization.id)
        assert response_json["approved"] is None
        assert response_json["updated_at"] is not None
        assert count == 1

    def test_fail_already_a_member(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_organization.owner.id, test_organization.id
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/organizations/{str(test_organization.id)}/request_access",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == "You are already a member of this Organization"
        
    def test_fail_request_already_exists(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/organizations/{str(test_organization.id)}/request_access",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            "You already requested access to this Organization. Your request awaits processing"
        )

    def test_fail_request_denied_recently(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False,
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/organizations/{str(test_organization.id)}/request_access",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"].startswith(
            "Your access request for this Organization was denied on"
        )


class TestMyOrganizationsAccessRequests:
    def test_success_default(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_users,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_users[0].id, test_organization.id,
        )
        create_test_organization_access_request(
            TestSession, test_users[1].id, test_organization.id,
        )
        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 2
        requester_ids = [access_request["requester_id"] for access_request in response_json]
        assert str(test_users[0].id) in requester_ids
        assert str(test_users[1].id) in requester_ids

    def test_success_all(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_user,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )
        create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False
        )
        create_test_organization_access_request(TestSession, test_user.id, test_organization.id)

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests?status=all",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 3

    def test_success_processed(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_user,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )
        create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False
        )
        create_test_organization_access_request(TestSession, test_user.id, test_organization.id)

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests?status=processed",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 2

    def test_success_unprocessed(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_users,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )
        create_test_organization_access_request(
            TestSession, test_users[0].id, test_organization.id,
        )
        create_test_organization_access_request(
            TestSession, test_users[1].id, test_organization.id,
        )

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests?status=unprocessed",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 2
        requester_ids = [access_request["requester_id"] for access_request in response_json]
        assert str(test_users[0].id) in requester_ids
        assert str(test_users[1].id) in requester_ids

    def test_success_approved(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_user,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )
        create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False
        )
        create_test_organization_access_request(TestSession, test_user.id, test_organization.id)

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests?status=approved",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 1

    def test_success_rejected(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_user,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service

        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )
        create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False
        )
        create_test_organization_access_request(TestSession, test_user.id, test_organization.id)

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests?status=approved",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 1

    def test_success_no_owned_organizations(
        self,
        TestSession,
        test_organization_access_request_service,
        test_user_service,
        test_organization,
        test_user,   
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[UserService] = lambda: test_user_service
        create_test_organization_access_request(
            TestSession, test_organization.members[0].id, test_organization.id, approved=True
        )

        client = TestClient(app)
        response = client.get(
            f"/auth/me/organizations/access_requests",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 0


class TestOrganizationAccessRequestProcess:
    @pytest.mark.parametrize(
        "decision, expected_message", 
        [
            (True, "Access request approved"), 
            (False, "Access request declined"),
        ],
    )
    def test_success(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
        decision,
        expected_message,

    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/access_requests/{str(access_request.id)}/process",
            headers=generate_auth_headers(test_organization.owner.email),
            json={"approve": decision}
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == expected_message
        access_request = test_organization_access_request_service.repository.get_by_id(
            str(access_request.id)
        )
        assert access_request.approved is decision

    @pytest.mark.parametrize(
        "decision, expected_message", 
        [
            (True, "Access request approved"), 
            (False, "Access request declined"),
        ],
    )
    def test_success_process_previously_declined_request(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
        decision,
        expected_message,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=False
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/access_requests/{str(access_request.id)}/process",
            headers=generate_auth_headers(test_organization.owner.email),
            json={"approve": decision}
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == expected_message
        access_request = test_organization_access_request_service.repository.get_by_id(
            str(access_request.id)
        )
        assert access_request.approved is decision

    @pytest.mark.parametrize("decision", [True, False])
    def test_failure_access_request_already_approved(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
        decision,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id, approved=True
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/access_requests/{str(access_request.id)}/process",
            headers=generate_auth_headers(test_organization.owner.email),
            json={"approve": decision}
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == "This access request has already been approved"

    @pytest.mark.parametrize("decision", [True, False])
    def test_failure_no_permission_to_process(
        self,
        TestSession,
        test_organization_access_request_service,
        test_organization_service,
        test_user_service,
        test_organization,
        test_user,
        decision,
    ):
        app.dependency_overrides[OrganizationAccessRequestService] = (
            lambda: test_organization_access_request_service
        )
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        app.dependency_overrides[UserService] = lambda: test_user_service

        access_request = create_test_organization_access_request(
            TestSession, test_user.id, test_organization.id
        )

        client = TestClient(app)
        response = client.post(
            f"/auth/me/organizations/access_requests/{str(access_request.id)}/process",
            headers=generate_auth_headers(test_user.email),
            json={"approve": decision}
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestBoardCreate:
    def test_success_with_defaults_as_owner(
        self, 
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        payload = {"name": "Test Board", "organization_id": str(test_organization.id)}
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()
        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 1
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 5
        assert [
            column["name"] for column in response_json["columns"]
        ] == [payload.name for payload in todo_constants.DEFAULT_COLUMNS]

    def test_success_with_defaults_as_member(
        self, 
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        payload = {"name": "Test Board", "organization_id": str(test_organization_with_members.id)}
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
            json=payload,
        )
        response_json = response.json()

        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 1
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 5
        assert [
            column["name"] for column in response_json["columns"]
        ] == [payload.name for payload in todo_constants.DEFAULT_COLUMNS]

    def test_success_copying_columns_as_owner(
        self, 
        TestSession,
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        existing_board = create_test_board(TestSession, "Existing Board", str(test_organization.id))
        existing_column = create_test_column(TestSession, "Test Column", str(existing_board.id), 1)

        payload = {
            "name": "Test Board", 
            "organization_id": str(test_organization.id), 
            "use_columns_from_board_id": str(existing_board.id),
        }
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 2
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 1
        assert response_json["columns"][0]["name"] == existing_column.name

    def test_success_copying_columns_as_member(
        self, 
        TestSession,
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        organization_id = str(test_organization_with_members.id)
        existing_board = create_test_board(TestSession, "Existing Board", organization_id)
        existing_column = create_test_column(TestSession, "Test Column", str(existing_board.id), 1)

        payload = {
            "name": "Test Board", 
            "organization_id": organization_id, 
            "use_columns_from_board_id": str(existing_board.id),
        }
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
            json=payload,
        )
        response_json = response.json()

        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 2
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 1
        assert response_json["columns"][0]["name"] == existing_column.name

    def test_success_copying_columns_from_board_of_affiliated_organization_as_owner(
        self, 
        TestSession,
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        affiliated_org = create_test_organization(
            TestSession, name="Affiliated org", owner=test_organization.owner,
        )
        existing_board = create_test_board(TestSession, "Existing Board", str(affiliated_org.id))
        existing_column = create_test_column(TestSession, "Test Column", str(existing_board.id), 1)

        payload = {
            "name": "Test Board", 
            "organization_id": str(test_organization.id), 
            "use_columns_from_board_id": str(existing_board.id),
        }
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 2
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 1
        assert response_json["columns"][0]["name"] == existing_column.name

    def test_success_copying_columns_from_board_of_affiliated_organization_as_owner(
        self, 
        TestSession,
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        me = test_organization_with_members.members[0]
        affiliated_org = create_test_organization(TestSession, name="Affiliated org", owner=me)
        existing_board = create_test_board(TestSession, "Existing Board", str(affiliated_org.id))
        existing_column = create_test_column(TestSession, "Test Column", str(existing_board.id), 1)

        payload = {
            "name": "Test Board", 
            "organization_id": str(test_organization_with_members.id), 
            "use_columns_from_board_id": str(existing_board.id),
        }
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(me.email),
            json=payload,
        )
        response_json = response.json()

        board_count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert board_count == 2
        assert response_json["organization_id"] == payload["organization_id"]
        assert response_json["name"] == payload["name"]
        assert response_json["id"]
        assert len(response_json["columns"]) == 1
        assert response_json["columns"][0]["name"] == existing_column.name

    def test_fail_user_outside_organization(
        self,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        payload = {"name": "Test Board", "organization_id": str(test_organization.id)}
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_duplicate_name(
        self,
        TestSession,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        test_board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        client = TestClient(app)

        payload = {"name": test_board.name, "organization_id": str(test_board.organization_id)}
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            f"This organization already has a Board named {test_board.name}"
        )

    def test_fail_copying_columns_from_board_of_unaffiliated_organization(
        self, 
        TestSession,
        test_board_repository,
        test_board_service, 
        test_column_service,
        test_user_service, 
        test_organization_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        unaffiliated_org = create_test_organization(
            TestSession, name="Unaffiliated org", owner=test_user,
        )
        existing_board = create_test_board(TestSession, "Existing Board", str(unaffiliated_org.id))
        existing_column = create_test_column(TestSession, "Test Column", str(existing_board.id), 1)

        payload = {
            "name": "Test Board", 
            "organization_id": str(test_organization.id), 
            "use_columns_from_board_id": str(existing_board.id),
        }
        response = client.post(
            "/todo/board",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestBoardsList:
    def test_success(
        self, 
        TestSession,
        test_board_service, 
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        board_names = []
        for i in range(1, 3):
            name = f"Test Board {i}"
            board_names.append(name)
            create_test_board(TestSession, name, str(test_organization.id))

        response = client.get(
            f"/todo/organizations/{str(test_organization.id)}/boards",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert len(response_json) == 2
        response_board_names = [board["name"] for board in response_json]
        for name in board_names:
            assert name in response_board_names

    def test_fail_not_member_of_organization(
        self, 
        test_board_service, 
        test_user_service, 
        test_organization_service,
        test_organization,
        test_user
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        response = client.get(
            f"/todo/organizations/{str(test_organization.id)}/boards",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestBoardDetails:
    def test_success(
        self, 
        TestSession,
        test_board_service, 
        test_column_service,
        test_task_service,
        test_user_service, 
        test_organization_service,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column_1 = create_test_column(TestSession, "Column 1", str(board.id), 1)
        column_2 = create_test_column(TestSession, "Column 2", str(board.id), 1)
        task_1 = create_test_task(
            TestSession, 
            "Task 1", 
            str(column_1.id),
            str(test_organization.owner_id),
            order=3,
            assigned_to=None,
        )
        task_2 = create_test_task(
            TestSession, 
            "Task 2", 
            str(column_1.id),
            str(test_organization.owner_id),
            order=1,
            assigned_to=None,
        )
        task_3 = create_test_task(
            TestSession, 
            "Task 3", 
            str(column_2.id),
            str(test_organization.owner_id),
            order=1,
            assigned_to=None,
        )

        response = client.get(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["organization_id"] == str(test_organization.id)
        assert response_json["name"] == board.name
        assert response_json["id"]
        assert len(response_json["columns"]) == 2
        assert len(response_json["columns"][0]["tasks"]) == 2
        # Order intentional!
        assert response_json["columns"][0]["tasks"][0]["name"] == task_2.name
        assert response_json["columns"][0]["tasks"][1]["name"] == task_1.name
        assert len(response_json["columns"][1]["tasks"]) == 1
        assert response_json["columns"][1]["tasks"][0]["name"] == task_3.name


    def test_fail_not_member_of_organization(
        self, 
        TestSession,
        test_board_service, 
        test_column_service,
        test_task_service,
        test_user_service, 
        test_organization_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        app.dependency_overrides[OrganizationService] = lambda: test_organization_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))

        response = client.get(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestBoardDelete: 
    def test_success_with_empty_columns(
        self, 
        TestSession, 
        test_board_service, 
        test_user_service, 
        test_board_repository,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        create_test_column(TestSession, "Column 1", str(board.id), 1)
        create_test_column(TestSession, "Column 2 Terminal", str(board.id), 2, True)

        response = client.delete(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == "Board deleted successfully"
        assert count == 0

    def test_success_with_tasks_in_terminal_column(
        self, 
        TestSession, 
        test_board_service, 
        test_user_service, 
        test_board_repository,
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        create_test_column(TestSession, "Column 1", str(board.id), 1)
        terminal = create_test_column(TestSession, "Column 2 Terminal", str(board.id), 2, True)
        create_test_task(TestSession, "Task", str(terminal.id), str(test_organization.owner_id), 1)
        create_test_task(TestSession, "Task", str(terminal.id), str(test_organization.owner_id), 2)

        response = client.delete(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        count = test_board_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == "Board deleted successfully"
        assert count == 0

    def test_fail_tasks_in_non_terminal_column(
        self, 
        TestSession, 
        test_board_service, 
        test_user_service, 
        test_organization,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Column 1", str(board.id), 1)
        terminal = create_test_column(TestSession, "Column 2 Terminal", str(board.id), 2, True)
        create_test_task(TestSession, "Task", str(column.id), str(test_organization.owner_id), 1)
        create_test_task(TestSession, "Task", str(terminal.id), str(test_organization.owner_id), 1)

        response = client.delete(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == "Cannot delete a board that has unfinished tasks"

    def test_fail_not_organization_owner(
        self, 
        TestSession, 
        test_board_service, 
        test_user_service, 
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))

        response = client.delete(
            f"/todo/board/{str(board.id)}",
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestColumnCreate:
    def test_success(
        self,
        TestSession,
        test_column_service,
        test_board_service,
        test_user_service,
        test_column_repository,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        payload = {"name": "New column", "order": 1337, "is_terminal": True}

        response = client.post(
            f"/todo/board/{str(board.id)}/columns",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()
        count = test_column_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json[0]["name"] == payload["name"]
        assert response_json[0]["board_id"] == str(board.id)
        assert response_json[0]["order"] == payload["order"]
        assert response_json[0]["is_terminal"] == payload["is_terminal"]
        assert count == 1

    def test_fail_not_an_owner_of_organization(
        self,
        TestSession,
        test_column_service,
        test_board_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        payload = {"name": "New column", "order": 1337, "is_terminal": True}

        response = client.post(
            f"/todo/board/{str(board.id)}/columns",
            headers=generate_auth_headers(test_user.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action" 

    def test_fail_column_name_not_unique(
        self,
        TestSession,
        test_column_service,
        test_board_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Existing", str(board.id), 0)
        payload = {"name": column.name, "order": 1337, "is_terminal": True}

        response = client.post(
            f"/todo/board/{str(board.id)}/columns",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload,
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            f"Column named {column.name} already exists for this board" 
        )


class TestColumnUpdate:
    # test success for each combination of the fields
    @pytest.mark.parametrize(
        "payload",
        [
            PartialUpdateColumnPayload(name="Terminal 1337", order=1337, is_terminal=True),
            PartialUpdateColumnPayload(name="1337", order=1337),
            PartialUpdateColumnPayload(name="Terminal", is_terminal=True),
            PartialUpdateColumnPayload(order=1337, is_terminal=True),
            PartialUpdateColumnPayload(name="New"),
            PartialUpdateColumnPayload(order=1337),
            PartialUpdateColumnPayload(is_terminal=True),
        ]
    )
    def test_success(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_organization,
        payload,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(
            TestSession, name="Unchanged name", board_id=str(board.id), order=1, is_terminal=False
        )

        response = client.patch(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
            json=payload.model_dump(),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        if payload.name is not None:
            assert response_json["name"] == payload.name
        if payload.order is not None:
            assert response_json["order"] == payload.order
        if payload.is_terminal is not None:
            assert response_json["is_terminal"] == payload.is_terminal

    def test_fail_bad_payload(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(
            TestSession, name="Unchanged name", board_id=str(board.id), order=1, is_terminal=False
        )

        response = client.patch(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
            json={},
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            "At least one of ['name', 'order', 'is_terminal'] needs to be present"
        )

    def test_fail_not_an_owner_of_organization(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(
            TestSession, name="Unchanged name", board_id=str(board.id), order=1, is_terminal=False
        )

        response = client.patch(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_user.email),
            json={"name": "New name"},
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestColumnDelete:
    def test_success(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_column_repository,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)

        response = client.delete(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        count = test_column_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == "Column deleted successfully"
        assert count == 0

    def test_success_terminal_column_with_tasks(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_column_repository,
        test_task_repository,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, True)
        create_test_task(TestSession, "Task", str(column.id), str(test_organization.owner_id), 0)

        response = client.delete(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        column_count = test_column_repository.get_count()
        task_count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["detail"] == "Column deleted successfully"
        assert column_count == 0
        assert task_count == 0

    def test_fail_non_terminal_column_with_tasks(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_column_repository,
        test_task_repository,
        test_organization,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        create_test_task(TestSession, "Task", str(column.id), str(test_organization.owner_id), 0)

        response = client.delete(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_organization.owner.email),
        )
        response_json = response.json()
        column_count = test_column_repository.get_count()
        task_count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            "Cannot delete a column that is not terminal and has tasks"
        )
        assert column_count == 1
        assert task_count == 1

    def test_fail_not_an_owner_of_organization(
        self,
        TestSession,
        test_column_service,
        test_user_service,
        test_column_repository,
        test_task_repository,
        test_organization,
        test_user,
    ):
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        create_test_task(TestSession, "Task", str(column.id), str(test_organization.owner_id), 0)

        response = client.delete(
            f"/todo/column/{str(column.id)}",
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"


class TestTaskCreate:
    def test_success_no_assignee_as_organization_owner(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_task_repository,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()
        count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["column_id"] == str(column.id)
        assert response_json["created_by"] == str(test_organization_with_members.owner.id)
        assert response_json["assigned_to"] == None
        assert response_json["name"] == payload["name"]
        assert response_json["order"] == payload["order"]
        assert count == 1

    def test_success_with_assignee_as_organization_owner(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_task_repository,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "assigned_to": str(test_organization_with_members.members[0].id),
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()
        count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["column_id"] == str(column.id)
        assert response_json["created_by"] == str(test_organization_with_members.owner.id)
        assert response_json["assigned_to"] == payload["assigned_to"]
        assert response_json["name"] == payload["name"]
        assert response_json["order"] == payload["order"]
        assert count == 1

    def test_success_no_assignee_as_organization_member(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_task_repository,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
        )
        response_json = response.json()
        count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["column_id"] == str(column.id)
        assert response_json["created_by"] == str(test_organization_with_members.members[0].id)
        assert response_json["assigned_to"] == None
        assert response_json["name"] == payload["name"]
        assert response_json["order"] == payload["order"]
        assert count == 1

    def test_success_with_assignee_as_organization_member(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_task_repository,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "assigned_to": str(test_organization_with_members.owner_id),
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.members[0].email),
        )
        response_json = response.json()
        count = test_task_repository.get_count()

        assert response.status_code == HTTPStatus.OK
        assert response_json["column_id"] == str(column.id)
        assert response_json["created_by"] == str(test_organization_with_members.members[0].id)
        assert response_json["assigned_to"] == payload["assigned_to"]
        assert response_json["name"] == payload["name"]
        assert response_json["order"] == payload["order"]
        assert count == 1

    def test_fail_creator_has_no_access_to_board(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_assignee_has_no_access_to_board(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column = create_test_column(TestSession, "Test Column", str(board.id), 0, False)
        payload = {
            "assigned_to": str(test_user.id),
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{str(column.id)}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_column_doesnt_exist(
        self,
        TestSession,
        test_board_service,
        test_column_service,
        test_task_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[BoardService] = lambda: test_board_service
        app.dependency_overrides[ColumnService] = lambda: test_column_service
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_id = "e6358d05-f648-4bc4-a251-08b087c801e8"
        payload = {
            "name": "Test Task",
            "description": "Lorem ipsum dolor sit amet",
            "order": 1337,
        }

        response = client.post(
            f"/todo/board/{str(board.id)}/column/{column_id}/tasks",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.NOT_FOUND
        assert response_json["detail"] == "Column not found"


class TestTaskPartialUpdate:
    # 6! is 720, we won't parameterize all of the options - only "special" and "expected" cases
    @pytest.mark.parametrize(
        "payload",
        [
            {
                "column_id": True, 
                "created_by": True, 
                "assigned_to": True, 
                "name": "New name", 
                "description": "New description",
                "order": 1337
            },
            {"column_id": True, "created_by": True, "order": 1337},
            {"column_id": True, "assigned_to": True, "order": 1337},
            {"column_id": True, "created_by": True, "assigned_to": True, "order": 1337},
            {"name": "New name",  "description": "New description"},
            {"column_id": True, "order": 1337},
            {"order": 1337},
        ]
    )
    def test_success(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        payload,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )

        if "column_id" in payload:
            payload["column_id"] = str(column_2.id)
        if "created_by" in payload:
            payload["created_by"] = str(test_organization_with_members.members[0].id)
        if "assigned_to" in payload:
            payload["assigned_to"] = str(test_organization_with_members.members[0].id)

        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.OK
        assert response_json["id"] == str(task.id)
        if "column_id" in payload:
            assert response_json["column_id"] == payload["column_id"]
        else:
            assert response_json["column_id"] == str(task.column_id)
        if "created_by" in payload:
            assert response_json["created_by"] == payload["created_by"]
        else:
            assert response_json["created_by"] == str(task.created_by)
        if "assigned_to" in payload:
            assert response_json["assigned_to"] == payload["assigned_to"]
        else:
            assert response_json["assigned_to"] == task.assigned_to
        if "name" in payload:
            assert response_json["name"] == payload["name"]
        else:
            assert response_json["name"] == task.name
        if "description" in payload: 
            assert response_json["description"] == payload["description"]
        else:
            assert response_json["description"] == task.description
        if "order" in payload: 
            assert response_json["order"] == payload["order"]
        else:
            assert response_json["order"] == task.order

    def test_fail_empty_payload(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )


        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json={},
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.UNPROCESSABLE_CONTENT
        assert response_json["detail"] == (
            "At least one of ['column_id', 'created_by', 'assigned_to', 'name', 'description', "
            "'order'] needs to be present"
        )

    def test_fail_new_created_by_not_a_member_of_organization(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )

        payload = {"created_by": str(test_user.id)}

        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_new_assigned_to_not_a_member_of_organization(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )

        payload = {"assigned_to": str(test_user.id)}

        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_new_created_by_and_assigned_to_not_members_of_organization(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )

        payload = {"created_by": str(test_user.id), "assigned_to": str(test_user.id)}

        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json=payload,
            headers=generate_auth_headers(test_organization_with_members.owner.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"

    def test_fail_not_a_member_of_organization(
        self,
        TestSession,
        test_task_service,
        test_user_service,
        test_organization_with_members,
        test_user,
    ):
        app.dependency_overrides[TaskService] = lambda: test_task_service
        app.dependency_overrides[UserService] = lambda: test_user_service
        client = TestClient(app)

        board = create_test_board(TestSession, "Test Board", str(test_organization_with_members.id))
        column_1 = create_test_column(TestSession, "TODO", str(board.id), 0, False)
        column_2 = create_test_column(TestSession, "Done", str(board.id), 1, True)
        task = create_test_task(
            TestSession, 
            name="Old name", 
            column_id=str(column_1.id), 
            created_by=str(test_organization_with_members.owner_id),
            assigned_to=None,
            order=0,
            description="Old description",
        )

        payload = {"created_by": str(test_user.id), "assigned_to": str(test_user.id)}

        response = client.patch(
            f"/todo/tasks/{str(task.id)}",
            json=payload,
            headers=generate_auth_headers(test_user.email),
        )
        response_json = response.json()

        assert response.status_code == HTTPStatus.FORBIDDEN
        assert response_json["detail"] == "You do not have the permission to perform this action"
