from alembic import context
from sqlalchemy import create_engine, pool

import app.models  # Registers SQLAlchemy models.
from app.core.config import get_settings
from app.core.model_base import Base

config = context.config
target_metadata = Base.metadata


def include_name(name, type_, parent_names):
    if type_ == "schema":
        return name == "payflow"
    return True


def run_migrations_offline():
    context.configure(
        url=get_settings().migration_database_url,
        target_metadata=target_metadata,
        literal_binds=True,
        version_table_schema="payflow",
        include_schemas=True,
        include_name=include_name,
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    engine = create_engine(
        get_settings().migration_database_url,
        poolclass=pool.NullPool,
        connect_args={
            "connect_timeout": 5,
            "options": "-csearch_path=public",
        },
    )

    try:
        with engine.connect() as connection:
            context.configure(
                connection=connection,
                target_metadata=target_metadata,
                version_table_schema="payflow",
                include_schemas=True,
                include_name=include_name,
                compare_type=True,
            )

            with context.begin_transaction():
                context.run_migrations()
    finally:
        engine.dispose()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
