import logging
from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.core.security import hash_password
from app.models import User
from app.models.entities import UserRole
from app.services.audit import record_audit


logger = logging.getLogger(__name__)


def bootstrap_admin() -> None:
    settings = get_settings()
    if not all((settings.initial_admin_username, settings.initial_admin_password, settings.initial_admin_email)):
        logger.info("initial admin bootstrap skipped: credentials not fully configured")
        return
    if len(settings.initial_admin_password.get_secret_value()) < 12:
        logger.warning("initial administrator password is shorter than the recommended 12 characters")
    with SessionLocal() as db:
        if db.scalar(select(User.id).limit(1)):
            return
        user = User(
            id=uuid4(),
            username=settings.initial_admin_username.strip(),
            password_hash=hash_password(settings.initial_admin_password.get_secret_value()),
            display_name=settings.initial_admin_display_name.strip(),
            email=settings.initial_admin_email.strip().lower(),
            role=UserRole.ADMIN,
            must_change_password=True,
        )
        db.add(user)
        record_audit(db, "ADMIN_BOOTSTRAPPED", "SYSTEM", None, "USER", user.id)
        try:
            db.commit()
            logger.info("initial administrator created")
        except IntegrityError:
            db.rollback()
            logger.info("initial administrator already created by another worker")
