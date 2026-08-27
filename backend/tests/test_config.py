import pytest
from pydantic import ValidationError

from app.core.config import Settings


def test_invalid_bootstrap_password_is_masked_in_configuration_error(monkeypatch):
    raw_password = "short7!"
    monkeypatch.delenv("INITIAL_ADMIN_PASSWORD")
    with pytest.raises(ValidationError) as captured:
        Settings(
            jwt_secret="a" * 32,
            api_key_pepper="b" * 32,
            initial_admin_password=raw_password,
            _env_file=None,
        )
    assert raw_password not in str(captured.value)
    assert "input_value=" not in str(captured.value)


def test_invalid_platform_secret_is_masked_in_configuration_error():
    raw_secret = "short-platform-secret"
    with pytest.raises(ValidationError) as captured:
        Settings(jwt_secret=raw_secret, api_key_pepper="b" * 32, _env_file=None)
    assert raw_secret not in str(captured.value)


def test_runtime_secret_files_build_database_configuration(tmp_path):
    jwt_file = tmp_path / "jwt"
    pepper_file = tmp_path / "pepper"
    password_file = tmp_path / "postgres"
    jwt_file.write_text("j" * 48)
    pepper_file.write_text("k" * 48)
    password_file.write_text("database-password-with-special-@:/")
    settings = Settings(
        database_url="", postgres_user="bypass", postgres_db="bypass",
        postgres_password=None, postgres_password_file=str(password_file),
        jwt_secret=None, jwt_secret_file=str(jwt_file),
        api_key_pepper=None, api_key_pepper_file=str(pepper_file), _env_file=None,
    )
    assert settings.jwt_secret.get_secret_value() == "j" * 48
    assert settings.api_key_pepper.get_secret_value() == "k" * 48
    assert "database-password-with-special-%40%3A%2F" in settings.database_url
