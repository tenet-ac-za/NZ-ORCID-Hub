import pytest
from peewee import SqliteDatabase
from itertools import product
from models import User, Organisation, UserOrg, Role, drop_talbes, create_tables
from playhouse.test_utils import test_database

@pytest.fixture
def test_db():
    """Peewee Test DB context.

    Example:

    def test_NAME(test_db):
        u = models.User(email="test@test.org", name="TESTER TESTERON")
        u.save()
        asser modls.User.count() == 1
    """
    _db = SqliteDatabase(":memory:")
    with test_database(_db, (Organisation, User, UserOrg,)) as _test_db:
        yield _test_db

    return


@pytest.fixture
def test_models(test_db):

    Organisation.insert_many((dict(
        name="Organisation #%d" % i,
        email="admin@org%d.org.nz" % i,
        tuakiri_name="Organisation #%d" % i,
        orcid_client_id="client-%d" % i,
        orcid_secret="secret-%d" % i,
        confirmed=(i % 2 == 0))
        for i in range(10))).execute()

    User.insert_many((dict(
        name="Test User #%d" % i,
        first_name="Test_%d" % i,
        last_name="User_%d" % i,
        email="user%d@org%d.org.nz" % (i, i * 4 % 10),
        edu_person_shared_token="EDU PERSON SHARED TOKEN #%d" % i,
        confirmed=(i % 3 != 0),
        roles=Role.SUPERUSER if i % 42 == 0 else Role.ADMIN if i % 13 == 0 else Role.RESEARCHER)
        for i in range(60))).execute()

    UserOrg.insert_many((dict(
        is_admin=((u + o) % 23 == 0),
        user=u,
        org=o) for (u, o) in product(range(2, 60, 4), range(2, 10)))).execute()

    UserOrg.insert_many((dict(
        is_admin=True,
        user=43,
        org=o) for o in range(1, 11))).execute()

    yield test_db


def test_user_org_link_user_constraint(test_models):
    org = Organisation.get(id=1)
    uo = UserOrg(user=999999, org=org)
    with pytest.raises(User.DoesNotExist):
        uo.save()


def test_user_org_link_org_constraint(test_models):
    user = User.get(id=1)
    uo = UserOrg(user=user, org=999999)
    with pytest.raises(Organisation.DoesNotExist):
        uo.save()


def test_org_count(test_models):
    assert Organisation.select().count() == 10


def test_user_count(test_models):
    assert User.select().count() == 60


def test_user_org_link(test_models):
    assert User.get(id=43).admin_for.count() == 10
    assert User.get(id=1).admin_for.count() == 0
    assert User.get(id=42).admin_for.count() > 0
    assert User.get(id=2).organisations.count() > 0
    assert Organisation.get(id=1).admins.count() == 1
    assert Organisation.get(id=5).users.count() > 0
    assert Organisation.get(id=5).admins.count() > 0


def test_roles(test_models):
    assert Role.RESEARCHER == "RESEARCHER"
    assert Role.RESEARCHER == Role["RESEARCHER"]
    assert Role.RESEARCHER != "ADMIN"
    assert Role.RESEARCHER != Role["ADMIN"]
    assert hash(Role.RESEARCHER) == hash("RESEARCHER")


def test_user_roles(test_models):
    user = User(
        name="Test User ABC123",
        first_name="ABC",
        last_name="123",
        email="user_abc_123@org.org.nz",
        edu_person_shared_token="EDU PERSON SHARED TOKEN ABC123",
        confirmed=True,
        roles=Role.ADMIN|Role.RESEARCHER)

    assert user.has_role(Role.ADMIN)
    assert user.has_role("ADMIN")
    assert user.has_role(Role.RESEARCHER)
    assert user.has_role("RESEARCHER")
    assert user.has_role(Role.RESEARCHER|Role.ADMIN)
    assert user.has_role(4)
    assert user.has_role(2)

    assert not user.has_role(Role.SUPERUSER)
    assert not user.has_role("SUPERUSER")
    assert not user.has_role(1)

    assert not user.has_role("NOT A ROLE")
    assert not user.has_role(~(1|2|4|8|16))


def test_admin_is_admin(test_models):
    user = User(
        name="Test User ABC123",
        first_name="ABC",
        last_name="123",
        email="user_abc_123@org.org.nz",
        edu_person_shared_token="EDU PERSON SHARED TOKEN ABC123",
        confirmed=True,
        roles=Role.ADMIN|Role.RESEARCHER)

    assert user.is_admin


def test_drop_tables(test_models):
    drop_talbes()
    assert not User.table_exists()
    assert not Organisation.table_exists()
    assert not UserOrg.table_exists()


def test_create_tables(test_models):
    drop_talbes()
    create_tables()
    assert User.table_exists()
    assert Organisation.table_exists()
    assert UserOrg.table_exists()