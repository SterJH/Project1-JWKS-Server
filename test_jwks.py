import main
from fastapi.testclient import TestClient

client = TestClient(main.app)


def test_auth_valid():
    """Test /auth returns a valid JWT"""
    response = client.post("/auth")
    assert response.status_code == 200
    body = response.json()
    assert "token" in body
    assert isinstance(body["token"], str)


def test_auth_expired():
    """Test /auth?expired=true returns an expired JWT"""
    response = client.post("/auth?expired=true")
    assert response.status_code == 200
    body = response.json()
    assert "token" in body
    assert isinstance(body["token"], str)


def test_auth_get_method_not_allowed():
    """GET on /auth should not be allowed"""
    response = client.get("/auth")
    assert response.status_code == 405


def test_jwks_contains_valid_key():
    """Test /jwks exposes the current JWK"""
    response = client.get("/jwks")
    assert response.status_code == 200
    body = response.json()
    assert "keys" in body
    keys = body["keys"]
    assert isinstance(keys, list)
    assert len(keys) > 0
    for key in keys:
        assert "kid" in key
        assert "kty" in key
        assert "n" in key
        assert "e" in key


def test_invalid_method_on_jwks():
    """POST on /jwks should not be allowed"""
    response = client.post("/jwks")
    assert response.status_code == 405
