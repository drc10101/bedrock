"""Tests for Anonymous ID generation."""

from bedrock.data_separation.anonymous_id import AnonymousID


class TestAnonymousID:
    """Test anonymous ID generation and validation."""

    def test_generate_format(self):
        gen = AnonymousID()
        anon_id = gen.generate()
        parts = anon_id.split("-")
        assert len(parts) == 3
        assert all(p.isalpha() for p in parts)

    def test_generate_unique(self):
        gen = AnonymousID()
        ids = {gen.generate() for _ in range(100)}
        # With 440M+ combinations, 100 should all be unique
        assert len(ids) == 100

    def test_combination_count(self):
        gen = AnonymousID()
        # 531 adjectives * 375 animals * 509 nouns = 101M+ combinations
        assert gen.combination_count > 100_000_000

    def test_validate_correct_format(self):
        assert AnonymousID.validate("crimson-arctic-fox") is True

    def test_validate_incorrect_format(self):
        assert AnonymousID.validate("invalid") is False
        assert AnonymousID.validate("too-many-parts-here") is False
        assert AnonymousID.validate("has-123-numbers") is False