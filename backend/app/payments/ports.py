"""Provider adapter interface.

No concrete gateway is instantiated here. Orchestration services
must select an authenticated merchant/provider configuration
before invoking an implementation of this interface.
"""

from typing import Protocol

from app.payments.contracts import (
    CreatePaymentCommand,
    CreateRefundCommand,
    FetchPaymentCommand,
    PaymentResult,
    RefundResult,
)


class PaymentProvider(Protocol):
    provider_code: str

    def create_payment(
        self,
        command: CreatePaymentCommand,
    ) -> PaymentResult:
        ...

    def fetch_payment(
        self,
        command: FetchPaymentCommand,
    ) -> PaymentResult:
        ...

    def create_refund(
        self,
        command: CreateRefundCommand,
    ) -> RefundResult:
        ...
