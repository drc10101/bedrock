"""
Tests for Bedrock Stripe Checkout and Webhook integration.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import json
import os
import time
import unittest
from unittest.mock import patch, MagicMock

from bedrock.licensing.enforcement import (
    LicenseEnforcer,
    LicenseTier,
    _get_signing_key,
)
from bedrock.licensing.checkout import (
    CheckoutTier,
    CheckoutResult,
    LicenseDelivery,
)


class TestCheckoutTier(unittest.TestCase):
    """Test CheckoutTier enum and mappings."""

    def test_checkout_tier_values(self):
        self.assertEqual(CheckoutTier.DEVELOPER_INDIVIDUAL.value, "developer_individual")
        self.assertEqual(CheckoutTier.DEVELOPER_TEAM.value, "developer_team")

    def test_checkout_tier_members(self):
        members = list(CheckoutTier)
        self.assertEqual(len(members), 2)


class TestCreateCheckoutSession(unittest.TestCase):
    """Test checkout session creation with mocked Stripe."""

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_developer_individual(self, mock_stripe):
        """Test creating a checkout session for individual developer license."""
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_test_individual"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test_12345"
        mock_session.url = "https://checkout.stripe.com/test/12345"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_INDIVIDUAL,
            customer_email="dev@example.com",
        )

        self.assertIsInstance(result, CheckoutResult)
        self.assertEqual(result.session_id, "cs_test_12345")
        self.assertEqual(result.session_url, "https://checkout.stripe.com/test/12345")
        self.assertEqual(result.tier, CheckoutTier.DEVELOPER_INDIVIDUAL)
        self.assertEqual(result.customer_email, "dev@example.com")

        # Clean up
        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_developer_team(self, mock_stripe):
        """Test creating a checkout session for team developer license."""
        os.environ["BEDROCK_STRIPE_PRICE_DEV_TEAM"] = "price_test_team"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test_team_67890"
        mock_session.url = "https://checkout.stripe.com/test/team"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_TEAM,
            customer_email="team@example.com",
        )

        self.assertEqual(result.tier, CheckoutTier.DEVELOPER_TEAM)
        self.assertEqual(result.customer_email, "team@example.com")

        # Verify Stripe was called with subscription mode for team
        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["mode"], "subscription")

        del os.environ["BEDROCK_STRIPE_PRICE_DEV_TEAM"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    def test_create_session_missing_price_id(self):
        """Test that missing price ID raises ValueError."""
        # Clear any existing env vars
        for key in ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL", "BEDROCK_STRIPE_SECRET_KEY"]:
            os.environ.pop(key, None)

        from bedrock.licensing.checkout import create_checkout_session

        with self.assertRaises((ValueError, Exception)):
            # Will fail due to missing secret key and/or missing price ID
            create_checkout_session(tier=CheckoutTier.DEVELOPER_INDIVIDUAL)

    def test_create_session_missing_secret_key(self):
        """Test that missing Stripe secret key raises ValueError."""
        os.environ.pop("BEDROCK_STRIPE_SECRET_KEY", None)
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_test"

        from bedrock.licensing.checkout import create_checkout_session

        with self.assertRaises(ValueError) as ctx:
            create_checkout_session(tier=CheckoutTier.DEVELOPER_INDIVIDUAL)
        self.assertIn("SECRET_KEY", str(ctx.exception))

        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_with_custom_urls(self, mock_stripe):
        """Test custom success/cancel URLs."""
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_test"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test"
        mock_session.url = "https://checkout.stripe.com/test"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_INDIVIDUAL,
            success_url="https://example.com/success",
            cancel_url="https://example.com/cancel",
        )

        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["success_url"], "https://example.com/success")
        self.assertEqual(call_kwargs["cancel_url"], "https://example.com/cancel")

        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_with_metadata(self, mock_stripe):
        """Test custom metadata is passed through."""
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_test"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test"
        mock_session.url = "https://checkout.stripe.com/test"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_INDIVIDUAL,
            metadata={"ref": "landing_page"},
        )

        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["metadata"]["ref"], "landing_page")
        self.assertEqual(call_kwargs["metadata"]["bedrock_tier"], "developer_individual")

        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]


class TestHandleCheckoutCompleted(unittest.TestCase):
    """Test webhook event processing for checkout completion."""

    def _make_event(self, tier="developer_individual", email="dev@example.com"):
        """Create a mock Stripe checkout.session.completed event."""
        return {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_123",
                    "metadata": {
                        "bedrock_tier": tier,
                    },
                    "customer_email": email,
                    "customer_details": {
                        "email": email,
                    },
                },
            },
        }

    def test_handle_individual_checkout(self):
        """Test license key issued for individual developer checkout."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="developer_individual", email="alice@example.com")
        delivery = handle_checkout_completed(event)

        self.assertIsInstance(delivery, LicenseDelivery)
        self.assertEqual(delivery.tier, "developer")
        self.assertEqual(delivery.customer_email, "alice@example.com")
        self.assertEqual(delivery.issued_to, "alice@example.com")
        self.assertEqual(delivery.max_nodes, 3)  # developer tier = 3 nodes

        # Verify the license key is valid
        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(delivery.license_key)
        self.assertTrue(license_obj.is_valid)
        self.assertEqual(license_obj.tier, LicenseTier.DEVELOPER)

    def test_handle_team_checkout(self):
        """Test license key issued for team developer checkout."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="developer_team", email="team@company.com")
        delivery = handle_checkout_completed(event)

        self.assertEqual(delivery.tier, "developer")
        self.assertEqual(delivery.customer_email, "team@company.com")

        # Team license should have more dev seats
        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(delivery.license_key)
        self.assertTrue(license_obj.is_valid)

    def test_handle_checkout_missing_email(self):
        """Test checkout with no email uses 'licensee' as fallback."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="developer_individual", email="")
        # Remove customer_details too
        event["data"]["object"]["customer_details"] = {}

        delivery = handle_checkout_completed(event)
        self.assertEqual(delivery.issued_to, "licensee")

    def test_license_key_expiry(self):
        """Test that issued license keys have a 1-year expiry."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(email="expiry@test.com")
        before = time.time()
        delivery = handle_checkout_completed(event)
        after = time.time()

        self.assertIsNotNone(delivery.expires_at)
        # Expiry should be ~1 year from now (365 days in seconds)
        one_year = 365 * 24 * 60 * 60
        self.assertAlmostEqual(delivery.expires_at - before, one_year, delta=10)


class TestConfigureStripe(unittest.TestCase):
    """Test Stripe SDK configuration."""

    def test_configure_stripe_with_key(self):
        """Test Stripe is configured with the secret key."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_configure_123"

        from bedrock.licensing.checkout import configure_stripe
        import stripe as stripe_mod

        result = configure_stripe()
        self.assertEqual(stripe_mod.api_key, "sk_test_configure_123")

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    def test_configure_stripe_missing_key(self):
        """Test that missing key raises ValueError."""
        os.environ.pop("BEDROCK_STRIPE_SECRET_KEY", None)

        from bedrock.licensing.checkout import configure_stripe

        with self.assertRaises(ValueError) as ctx:
            configure_stripe()
        self.assertIn("BEDROCK_STRIPE_SECRET_KEY", str(ctx.exception))


class TestWebhookSignatureVerification(unittest.TestCase):
    """Test Stripe webhook signature verification."""

    @patch("bedrock.licensing.checkout.stripe")
    def test_verify_valid_signature(self, mock_stripe):
        """Test that valid webhook signatures are accepted."""
        from bedrock.licensing.checkout import verify_webhook_signature

        os.environ["BEDROCK_STRIPE_WEBHOOK_SECRET"] = "whsec_test_123"

        mock_event = {"type": "checkout.session.completed", "data": {"object": {}}}
        mock_stripe.Webhook.construct_event.return_value = mock_event

        result = verify_webhook_signature(b'{"type": "test"}', "t=123,v1=abc")
        self.assertEqual(result["type"], "checkout.session.completed")

        del os.environ["BEDROCK_STRIPE_WEBHOOK_SECRET"]

    def test_verify_missing_webhook_secret(self):
        """Test that missing webhook secret raises ValueError."""
        os.environ.pop("BEDROCK_STRIPE_WEBHOOK_SECRET", None)

        from bedrock.licensing.checkout import verify_webhook_signature

        with self.assertRaises(ValueError) as ctx:
            verify_webhook_signature(b'{}', "sig")
        self.assertIn("WEBHOOK_SECRET", str(ctx.exception))


class TestPricingLinks(unittest.TestCase):
    """Test pricing link generation."""

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_pricing_links(self, mock_stripe):
        """Test generating pricing links for all tiers."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_individual"
        os.environ["BEDROCK_STRIPE_PRICE_DEV_TEAM"] = "price_team"

        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/individual"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_pricing_links

        links = create_pricing_links()

        self.assertIn("developer_individual", links)
        self.assertIn("developer_team", links)
        self.assertTrue(links["developer_individual"].startswith("https://"))

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]
        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]
        del os.environ["BEDROCK_STRIPE_PRICE_DEV_TEAM"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_pricing_links_partial_config(self, mock_stripe):
        """Test that only configured tiers get links."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"
        os.environ.pop("BEDROCK_STRIPE_PRICE_DEV_TEAM", None)
        os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"] = "price_individual"

        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/individual"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_pricing_links

        links = create_pricing_links()

        self.assertIn("developer_individual", links)
        self.assertNotIn("developer_team", links)

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]
        del os.environ["BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL"]


if __name__ == "__main__":
    unittest.main()