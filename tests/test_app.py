import os
import tempfile
import pytest

@pytest.fixture()
def client(tmp_path, monkeypatch):
    db_path = tmp_path / "test_securevault.db"
    monkeypatch.setenv("SECUREVAULT_DB", str(db_path))
    # Import after setting DB path so tests use a temporary database.
    import importlib
    import app as securevault
    securevault.DATABASE_PATH = str(db_path)
    securevault.init_db()
    securevault.app.config.update(TESTING=True, SECRET_KEY="test-secret")
    with securevault.app.test_client() as test_client:
        yield test_client


def register(client, username="test_user", password="StrongPass1!"):
    return client.post("/register", data={"username": username, "password": password}, follow_redirects=True)


def login(client, username="test_user", password="StrongPass1!"):
    return client.post("/login", data={"username": username, "password": password}, follow_redirects=True)


def test_home_and_health(client):
    assert client.get("/").status_code == 200
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json["status"] == "ok"


def test_register_success_and_login(client):
    response = register(client)
    assert response.status_code == 200
    assert b"Account created" in response.data
    response = login(client)
    assert b"Welcome, test_user" in response.data


def test_weak_password_rejected(client):
    response = register(client, password="weak")
    assert b"at least 10 characters" in response.data
    response = login(client)
    assert b"Welcome, test_user" not in response.data


def test_duplicate_username_rejected(client):
    register(client)
    response = register(client)
    assert b"already registered" in response.data

def test_wrong_password_does_not_authenticate(client):
    register(client)
    response = login(client, password="WrongPass1!")
    assert b"Invalid username or password" in response.data

    response = client.get("/dashboard")
    assert response.status_code == 302
    assert response.headers["Location"].endswith("/login")


def test_dashboard_requires_login(client):
    response = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in" in response.data


def test_repeated_failures_trigger_lockout(client):
    register(client)
    for _ in range(5):
        login(client, password="WrongPass1!")
    response = login(client, password="StrongPass1!")
    assert b"Too many failed attempts" in response.data


def test_logout_clears_session(client):
    register(client)
    login(client)
    response = client.get("/logout", follow_redirects=True)
    assert b"You have been logged out" in response.data
    response = client.get("/dashboard", follow_redirects=True)
    assert b"Please log in" in response.data
