"""Monitoring module for Netsleuth with OpenTelemetry integration."""

from __future__ import annotations

import logging
from contextlib import contextmanager
from typing import Any, Generator

logger = logging.getLogger(__name__)

try:
    from opentelemetry import trace
    from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    from opentelemetry.semconv.resource import ResourceAttributes

    OTEL_AVAILABLE = True
except ImportError:
    OTEL_AVAILABLE = False
    logger.warning("OpenTelemetry not available. Install with: pip install opentelemetry-api")


def setup_otel_tracing(
    service_name: str = "netsleuth",
    exporter_endpoint: str | None = None,
    resource_attributes: dict[str, Any] | None = None,
) -> bool:
    """
    Set up OpenTelemetry tracing for Netsleuth.

    Args:
        service_name: Name of the service for tracing
        exporter_endpoint: OTLP exporter endpoint (default: http://localhost:4317)
        resource_attributes: Additional resource attributes

    Returns:
        True if setup successful, False otherwise
    """
    if not OTEL_AVAILABLE:
        logger.warning("OpenTelemetry not available, skipping tracing setup")
        return False

    try:
        # Create resource with service information
        attributes = {
            ResourceAttributes.SERVICE_NAME: service_name,
            ResourceAttributes.SERVICE_VERSION: "0.1.0",
        }
        if resource_attributes:
            attributes.update(resource_attributes)

        resource = Resource.create(attributes)

        # Set up tracer provider
        tracer_provider = TracerProvider(resource=resource)

        # Add OTLP exporter if endpoint provided
        if exporter_endpoint:
            exporter = OTLPSpanExporter(endpoint=exporter_endpoint)
            tracer_provider.add_span_processor(BatchSpanProcessor(exporter))

        # Set as global tracer provider
        trace.set_tracer_provider(tracer_provider)

        logger.info(f"OpenTelemetry tracing configured for {service_name}")
        return True

    except Exception as e:
        logger.error(f"Failed to set up OpenTelemetry: {e}")
        return False


@contextmanager
def trace_operation(
    operation_name: str,
    span_attributes: dict[str, Any] | None = None,
) -> Generator[None, None, None]:
    """
    Context manager for tracing operations.

    Args:
        operation_name: Name of the operation to trace
        span_attributes: Optional attributes to add to the span

    Yields:
        None

    Example:
        >>> with trace_operation("network_diagnostic", {"target": "example.com"}):
        ...     run_diagnostic()
    """
    if OTEL_AVAILABLE:
        tracer = trace.get_tracer(__name__)
        with tracer.start_as_current_span(operation_name) as span:
            if span_attributes:
                for key, value in span_attributes.items():
                    span.set_attribute(key, value)
            yield
    else:
        yield


def record_metric(
    metric_name: str,
    value: float,
    attributes: dict[str, Any] | None = None,
) -> None:
    """
    Record a metric value.

    Args:
        metric_name: Name of the metric
        value: Metric value
        attributes: Optional attributes for the metric
    """
    # TODO: Implement metrics with OpenTelemetry metrics API
    logger.debug(f"Metric {metric_name}: {value}")


class HealthChecker:
    """Health check monitor for Netsleuth components."""

    def __init__(self) -> None:
        self._checks: dict[str, callable] = {}
        self._status: dict[str, bool] = {}

    def register_check(self, name: str, check_func: callable) -> None:
        """Register a health check function."""
        self._checks[name] = check_func

    async def run_checks(self) -> dict[str, bool]:
        """Run all registered health checks."""
        for name, check_func in self._checks.items():
            try:
                result = check_func()
                self._status[name] = result
            except Exception as e:
                logger.error(f"Health check {name} failed: {e}")
                self._status[name] = False
        return self._status

    def get_status(self) -> dict[str, bool]:
        """Get current health status."""
        return self._status.copy()

    def is_healthy(self) -> bool:
        """Check if all components are healthy."""
        return all(self._status.values())


# Default health checker instance
health_checker = HealthChecker()


def setup_monitoring(
    enable_tracing: bool = True,
    otel_endpoint: str | None = None,
    service_name: str = "netsleuth",
) -> bool:
    """
    Set up comprehensive monitoring for Netsleuth.

    Args:
        enable_tracing: Enable distributed tracing
        otel_endpoint: OpenTelemetry collector endpoint
        service_name: Service name for telemetry

    Returns:
        True if monitoring setup successful
    """
    success = True

    if enable_tracing:
        success = setup_otel_tracing(
            service_name=service_name,
            exporter_endpoint=otel_endpoint,
        )

    # Register default health checks
    health_checker.register_check("core", lambda: True)
    health_checker.register_check("cli", lambda: True)

    logger.info("Monitoring setup completed")
    return success


__all__ = [
    "setup_otel_tracing",
    "trace_operation",
    "record_metric",
    "HealthChecker",
    "health_checker",
    "setup_monitoring",
    "OTEL_AVAILABLE",
]
