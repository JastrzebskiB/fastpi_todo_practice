from http import HTTPStatus
from unittest.mock import patch

from fastapi.testclient import TestClient
from sqlalchemy.orm import joinedload

from src.auth.models import Organization
from src.auth.repositories import OrganizationRepository, UserRepository
from src.auth.services import OrganizationService, UserService
from src.auth.views import get_organization_service, get_user_service
from src.main import app


def test_user_create(test_user_service, test_user_repository):
    hash_password_return_value = "hashed_password"
    test_user_service.hash_password = lambda x: hash_password_return_value
    app.dependency_overrides[UserService] = lambda: test_user_service
    client = TestClient(app)

    payload = {"email": "test@test.com", "username": "test", "password": "not_hashed"}
    response = client.post("/auth/users", json=payload)
    response_json = response.json()

    user_count = test_user_repository.get_count()
    users = test_user_repository.get_all()

    assert response.status_code == HTTPStatus.OK
    assert user_count == 1
    assert response_json["owned_organization"] is None
    assert response_json["organization"] is None
    assert str(users[0].id) == response.json()["id"]
    assert users[0].email == payload["email"] == response_json["email"]
    assert users[0].username == payload["username"] == response_json["username"]
    assert users[0].password_hash == hash_password_return_value


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


def test_organization_list(
    test_organization_service, 
    test_organization_repository, 
    test_user_service,
    test_organization,
):
    app.dependency_overrides[get_organization_service] = lambda: test_organization_service
    app.dependency_overrides[get_user_service] = lambda: test_user_service

    client = TestClient(app)
    response = client.get("/auth/organizations")
    response_json = response.json()
