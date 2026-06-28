"""
End-to-end Stripe checkout test using real Stripe test keys.

This test requires environment variables:
  BEDROCK_STRIPE_SECRET_KEY: Stripe test mode secret key (sk_test_...)
  BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL: Price ID for individual dev tier
  BEDROCK_STRIPE_PRICE_DEV_TEAM: Price ID for team dev tier
  BEDROCK_STRIPE_PRODUCT_ID: Stripe product ID for Bedrock (optional)

If any of these are missing, the test is skipped.

SPDX-License-Identifier: BSL-1.1 — See LICENSE for details.
"""

import os
import unittest

STRIPE_KEY = os.environ.get("BEDROCK_STRIPE_SECRET_KEY", "")
SKIP_REASON = (
    "Set BEDROCK_STRIPE_SECRET_KEY, BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL, "
    "and BEDROCK_STRIPE_PRICE_DEV_TEAM environment variables to run E2E tests."
)


@unittest.skipUnless(
    STRIPE_KEY.startswith("sk_test_")
    and os.environ.get("BEDROCK_STRIPE_PRICE_DEV_INDIVIDUAL")
    and os.environ.get("BEDROCK_STRIPE_PRICE_DEV_TEAM"),
    SKIP_REASON,
)
class TestStripeE2ECheckout(unittest.TestCase):
    """Live Stripe checkout session creation and webhook processing."""

    def test_create_individual_checkout_session(self):
        """Create a real Stripe checkout session for individual dev tier."""
        from bedrock.licensing.checkout import create_checkout_session, CheckoutTier

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_INDIVIDUAL,
            customer_email="test-e2e@infill.systems",
        )

        self.assertTrue(result.session_id.startswith("cs_test_"))
        self.assertTrue(result.session_url.startswith("https://checkout.stripe.com/"))
        self.assertEqual(result.tier, CheckoutTier.DEVELOPER_INDIVIDUAL)
        self.assertEqual(result.customer_email, "test-e2e@infill.systems")

    def test_create_team_checkout_session(self):
        """Create a real Stripe checkout session for team dev tier."""
        from bedrock.licensing.checkout import create_checkout_session, CheckoutTier

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_TEAM,
            customer_email="team-e2e@infill.systems",
        )

        self.assertTrue(result.session_id.startswith("cs_test_"))
        self.assertTrue(result.session_url.startswith("https://checkout.stripe.com/"))
        self.assertEqual(result.tier, CheckoutTier.DEVELOPER_TEAM)

    def test_verify_session_on_stripe(self):
        """Verify the checkout session exists on Stripe."""
        import stripe

        from bedrock.licensing.checkout import create_checkout_session, CheckoutTier

        result = create_checkout_session(
            tier=CheckoutTier.DEVELOPER_INDIVIDUAL,
            customer_email="verify-e2e@infill.systems",
        )

        stripe.api_key = os.environ["BEDROCK_STRIPE_SECRET_KEY"]
        session = stripe.checkout.Session.retrieve(result.session_id)

        self.assertEqual(session.status, "open")
        self.assertEqual(session.mode, "subscription")

    def test_handle_checkout_completed_webhook(self):
        """Simulate checkout.session.completed webhook — license key delivery."""
        from bedrock.licensing.checkout import handle_checkout_completed
        from bedrock.licensing.enforcement import LicenseEnforcer

        event = {
            "type": "checkout.session.completed",
            "data": {
                "object": {
                    "id": "cs_test_e2e_webhook",
                    "metadata": {"bedrock_tier": "developer_individual"},
                    "customer_email": "e2e-test@infill.systems",
                    "customer_details": {"email": "e2e-test@infill.systems"},
                },
            },
        }

        delivery = handle_checkout_completed(event)

        self.assertEqual(delivery.tier, "developer")
        self.assertEqual(delivery.customer_email, "e2e-test@infill.systems")
        self.assertEqual(delivery.issued_to, "e2e-test@infill.systems")
        self.assertIsNotNone(delivery.expires_at)

        # Validate the issued license key
        enforcer = LicenseEnforcer()
        license_obj = enforcer.validate_license(delivery.license_key)
        self.assertTrue(license_obj.is_valid)
        self.assertEqual(license_obj.tier.value, "developer")

    def test_create_pricing_links(self):
        """Generate pricing links for all configured tiers."""
        from bedrock.licensing.checkout import create_pricing_links

        links = create_pricing_links()

        self.assertIn("developer_individual", links)
        self.assertIn("developer_team", links)
        for tier_name, url in links.items():
            self.assertTrue(
                url.startswith("https://checkout.stripe.com/"),
                f"Expected checkout URL for {tier_name}, got: {url}",
            )


if __name__ == "__main__":
    unittest.main()
