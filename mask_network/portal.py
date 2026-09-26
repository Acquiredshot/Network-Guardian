"""Mask Network public API — anonymisation and redaction primitives.


This module is the entry point for consumers that need to scrub,
mask, or anonymise data and network flows before they leave a
trusted boundary.
"""


class TrafficMasker:
    """Anonymise or redact network traffic based on a policy.

    Applies configured masking rules (deletion, substitution,
    generalisation, perturbation) to payloads in transit or at rest.
    """

    def mask(self, *, payload: bytes, rule_set: str) -> bytes:
        """Apply a masking rule set to a payload.

        Args:
            payload: Raw bytes to be masked.
            rule_set: Name of the rule set to apply.

        Returns:
            The masked bytes.
        """
        pass

    def redact_field(self, *, field_name: str, value: str) -> str:
        """Redact a single sensitive field value.

        Args:
            field_name: Logical name of the field (used for rule lookup).
            value: The raw value to redact.

        Returns:
            A redacted or masked replacement string.
        """
        pass


class AnonymisationPipeline:
    """Chain multiple anonymisation / masking steps into one callable.

    Pipelines are constructed from a list of named stages and applied
    sequentially; output of stage N becomes input of stage N+1.
    """

    def add_stage(self, *, name: str, masker: TrafficMasker) -> None:
        """Register a masking stage in the pipeline.

        Args:
            name: Human-readable stage name.
            masker: The TrafficMasker (or equivalent) for this stage.
        """
        pass

    def run(self, *, payload: bytes) -> bytes:
        """Run the pipeline against a payload.

        Args:
            payload: Raw bytes to process through all stages.

        Returns:
            The fully anonymised bytes.
        """
        pass
