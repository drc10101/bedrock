"""
Tests for Bedrock Stripe Checkout and Webhook integration.

Checkout tiers are now production-only (Starter, Business, Enterprise).
Developer licenses are free and issued via `bedrock dev`, not Stripe.

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
        self.assertEqual(CheckoutTier.STARTER.value, "starter")
        self.assertEqual(CheckoutTier.BUSINESS.value, "business")
        self.assertEqual(CheckoutTier.ENTERPRISE.value, "enterprise")

    def test_checkout_tier_members(self):
        members = list(CheckoutTier)
        self.assertEqual(len(members), 3)


class TestCreateCheckoutSession(unittest.TestCase):
    """Test checkout session creation with mocked Stripe."""

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_starter(self, mock_stripe):
        """Test creating a checkout session for Starter tier."""
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_test_starter"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test_12345"
        mock_session.url = "https://checkout.stripe.com/test/12345"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.STARTER,
            customer_email="customer@example.com",
        )

        self.assertIsInstance(result, CheckoutResult)
        self.assertEqual(result.session_id, "cs_test_12345")
        self.assertEqual(result.session_url, "https://checkout.stripe.com/test/12345")
        self.assertEqual(result.tier, CheckoutTier.STARTER)
        self.assertEqual(result.customer_email, "customer@example.com")

        # Clean up
        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_business(self, mock_stripe):
        """Test creating a checkout session for Business tier."""
        os.environ["BEDROCK_STRIPE_PRICE_BUSINESS"] = "price_test_business"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test_team_67890"
        mock_session.url = "https://checkout.stripe.com/test/business"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.BUSINESS,
            customer_email="biz@company.com",
        )

        self.assertEqual(result.tier, CheckoutTier.BUSINESS)
        self.assertEqual(result.customer_email, "biz@company.com")

        # Verify Stripe was called with subscription mode
        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["mode"], "subscription")

        del os.environ["BEDROCK_STRIPE_PRICE_BUSINESS"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    def test_create_session_enterprise_raises(self):
        """Test that Enterprise tier raises ValueError (custom pricing)."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        from bedrock.licensing.checkout import create_checkout_session

        with self.assertRaises(ValueError) as ctx:
            create_checkout_session(tier=CheckoutTier.ENTERPRISE)
        self.assertIn("custom pricing", str(ctx.exception))

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    def test_create_session_missing_price_id(self):
        """Test that missing price ID raises ValueError."""
        for key in ["BEDROCK_STRIPE_PRICE_STARTER", "BEDROCK_STRIPE_SECRET_KEY"]:
            os.environ.pop(key, None)

        from bedrock.licensing.checkout import create_checkout_session

        with self.assertRaises((ValueError, Exception)):
            create_checkout_session(tier=CheckoutTier.STARTER)

    def test_create_session_missing_secret_key(self):
        """Test that missing Stripe secret key raises ValueError."""
        os.environ.pop("BEDROCK_STRIPE_SECRET_KEY", None)
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_test"

        from bedrock.licensing.checkout import create_checkout_session

        with self.assertRaises(ValueError) as ctx:
            create_checkout_session(tier=CheckoutTier.STARTER)
        self.assertIn("SECRET_KEY", str(ctx.exception))

        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_with_custom_urls(self, mock_stripe):
        """Test custom success/cancel URLs."""
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_test"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test"
        mock_session.url = "https://checkout.stripe.com/test"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.STARTER,
            success_url="https://example.com/success",
            cancel_url="https://example.com/cancel",
        )

        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["success_url"], "https://example.com/success")
        self.assertEqual(call_kwargs["cancel_url"], "https://example.com/cancel")

        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_session_with_metadata(self, mock_stripe):
        """Test custom metadata is passed through."""
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_test"
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"

        mock_session = MagicMock()
        mock_session.id = "cs_test"
        mock_session.url = "https://checkout.stripe.com/test"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_checkout_session

        result = create_checkout_session(
            tier=CheckoutTier.STARTER,
            metadata={"ref": "landing_page"},
        )

        call_kwargs = mock_stripe.checkout.Session.create.call_args[1]
        self.assertEqual(call_kwargs["metadata"]["ref"], "landing_page")
        self.assertEqual(call_kwargs["metadata"]["bedrock_tier"], "starter")

        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]
        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]


class TestHandleCheckoutCompleted(unittest.TestCase):
    """Test webhook event processing for checkout completion."""

    def _make_event(self, tier="starter", email="customer@example.com"):
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

    def test_handle_starter_checkout(self):
        """Test license key issued for Starter checkout."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="starter", email="alice@example.com")
        delivery = handle_checkout_completed(event)

        self.assertIsInstance(delivery, LicenseDelivery)
        self.assertEqual(delivery.tier, "starter")
        self.assertEqual(delivery.customer_email, "alice@example.com")
        self.assertEqual(delivery.issued_to, "alice@example.com")

        # Verify the license key is valid and at Starter tier
        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(delivery.license_key)
        self.assertTrue(license_obj.is_valid)
        self.assertEqual(license_obj.tier, LicenseTier.STARTER)

    def test_handle_business_checkout(self):
        """Test license key issued for Business checkout."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="business", email="biz@company.com")
        delivery = handle_checkout_completed(event)

        self.assertEqual(delivery.tier, "business")
        self.assertEqual(delivery.customer_email, "biz@company.com")

        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(delivery.license_key)
        self.assertTrue(license_obj.is_valid)
        self.assertEqual(license_obj.tier, LicenseTier.BUSINESS)

    def test_handle_checkout_missing_email(self):
        """Test checkout with no email uses 'licensee' as fallback."""
        from bedrock.licensing.checkout import handle_checkout_completed

        event = self._make_event(tier="starter", email="")
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
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_tes..._123"

        from bedrock.licensing.checkout import configure_stripe
        import stripe as stripe_mod

        result = configure_stripe()
        self.assertEqual(stripe_mod.api_key, "sk_tes..._123")

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
        """Test generating pricing links for Starter and Business."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_starter"
        os.environ["BEDROCK_STRIPE_PRICE_BUSINESS"] = "price_business"

        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/starter"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_pricing_links

        links = create_pricing_links()

        self.assertIn("starter", links)
        self.assertIn("business", links)
        self.assertTrue(links["starter"].startswith("https://"))

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]
        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]
        del os.environ["BEDROCK_STRIPE_PRICE_BUSINESS"]

    @patch("bedrock.licensing.checkout.stripe")
    def test_create_pricing_links_partial_config(self, mock_stripe):
        """Test that only configured tiers get links."""
        os.environ["BEDROCK_STRIPE_SECRET_KEY"] = "sk_test_123"
        os.environ.pop("BEDROCK_STRIPE_PRICE_BUSINESS", None)
        os.environ["BEDROCK_STRIPE_PRICE_STARTER"] = "price_starter"

        mock_session = MagicMock()
        mock_session.url = "https://checkout.stripe.com/pay/starter"
        mock_stripe.checkout.Session.create.return_value = mock_session

        from bedrock.licensing.checkout import create_pricing_links

        links = create_pricing_links()

        self.assertIn("starter", links)
        self.assertNotIn("business", links)

        del os.environ["BEDROCK_STRIPE_SECRET_KEY"]
        del os.environ["BEDROCK_STRIPE_PRICE_STARTER"]


if __name__ == "__main__":
    unittest.main()