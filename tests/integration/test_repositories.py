from src.auth.dto import CreateUserPayload
from src.auth.models import User


def test_get_all(TestUserRepository, test_users):
    users = TestUserRepository.get_all()
    
    assert len(users) == 2
    for user in users:
        assert isinstance(user, User)


# TODO: Parameterize this, maybe split "negative" cases into a separate test?
def test_filter_by_first(TestUserRepository, test_users):
    # Test querying by single field
    filters = (User.username == "test_1",)
    user = TestUserRepository.filter_by_first(filters)

    assert isinstance(user, User)
    assert user.username == "test_1"
    assert user.email == "test_1@test.com"

    # Test querying by multiple fields
    filters = (User.username == "test_2", User.email == "test_2@test.com")
    user = TestUserRepository.filter_by_first(filters)

    assert isinstance(user, User)
    assert user.username == "test_2"
    assert user.email == "test_2@test.com"

    # Test querying with no result
    filters = (User.username == "bad", User.email == "bad")
    user = TestUserRepository.filter_by_first(filters)
    assert not user


# TODO: Parameterize this, maybe split "negative" cases into a separate test?
def test_filter_by_all(TestUserRepository, test_users):
    # Test querying by single field
    filters = (User.email.ilike("%@test.com"),)
    users = TestUserRepository.filter_by_all(filters)
    
    assert len(users) == 2
    for user in users:
        assert isinstance(user, User)
        assert "@test.com" in user.email

    # Test querying by multiple fields
    filters = (User.username.ilike("test%"), User.email.ilike("%@test.com"))
    users = TestUserRepository.filter_by_all(filters)

    assert len(users) == 2
    for user in users:
        assert isinstance(user, User)
        assert "@test.com" in user.email

    # Test querying with no result
    filters = (User.username.ilike("%bad%"), User.email.ilike("%bad%"))
    users = TestUserRepository.filter_by_first(filters)
    assert not users


def test_create(TestUserRepository):
    # TODO: Is this assertion needed?
    users = TestUserRepository.get_all()
    assert not users

    payload = CreateUserPayload(
        email="test@test.com",
        username="test",
        password_hash="hashed_password",  # Will be hashed in create_user_service
    )
    user = TestUserRepository.create(payload)

    users = TestUserRepository.get_all()
    assert len(users) == 1
