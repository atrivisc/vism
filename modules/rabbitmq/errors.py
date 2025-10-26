# Licensed under GPL 3: https://www.gnu.org/licenses/gpl-3.0.html
"""Rabbitmq module exception classes."""

from shared.errors import VismException


class RabbitMQError(VismException):
    """Raised when a RabbitMQ error occurs."""
