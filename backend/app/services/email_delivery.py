import smtplib
import ssl
from email.message import EmailMessage
from typing import Protocol

from app.core.config import get_settings


class VerificationEmailSender(Protocol):
    def send_verification(
        self,
        recipient: str,
        token: str,
    ) -> None:
        ...


class SmtpVerificationEmailSender:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        username: str,
        password: str,
        from_email: str,
    ):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self.from_email = from_email

    def send_verification(
        self,
        recipient: str,
        token: str,
    ) -> None:
        message = EmailMessage()
        message["From"] = self.from_email
        message["To"] = recipient
        message["Subject"] = "Verify your PayFlow account"

        message.set_content(
            "Welcome to PayFlow.\n\n"
            "Your email verification token is:\n\n"
            f"{token}\n\n"
            "This token expires in 24 hours. "
            "If you did not register, ignore this email.\n"
        )

        context = ssl.create_default_context()

        with smtplib.SMTP(
            self.host,
            self.port,
            timeout=10,
        ) as smtp:
            smtp.ehlo()

            if not smtp.has_extn("starttls"):
                raise RuntimeError(
                    "SMTP server does not support STARTTLS"
                )

            smtp.starttls(context=context)
            smtp.ehlo()
            smtp.login(self.username, self.password)
            smtp.send_message(message)


def get_verification_sender() -> VerificationEmailSender | None:
    settings = get_settings()

    values = (
        settings.smtp_host,
        settings.smtp_username,
        settings.smtp_password,
        settings.smtp_from_email,
    )

    if not any(values):
        # No SMTP configuration means no email is sent.
        return None

    if not all(values):
        raise RuntimeError(
            "SMTP configuration is incomplete"
        )

    return SmtpVerificationEmailSender(
        host=settings.smtp_host,
        port=settings.smtp_port,
        username=settings.smtp_username,
        password=settings.smtp_password.get_secret_value(),
        from_email=settings.smtp_from_email,
    )
