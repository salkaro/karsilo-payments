from src.database import Database

import stripe


async def run_initial_subscription_check():
    print("Running initial subscription check...")
    # Note: 'organisation' refers to database and 'customer' refers to stripe
    db = Database()

    try:
        organisations = await db.query_organisation_stream()

        async for doc in organisations:
            ref = doc.reference
            organisation = doc.to_dict()

            stripe_customer_id = organisation.get("stripeCustomerId")
            if stripe_customer_id is None:
                continue

            organisation_subscription = organisation.get("subscription")

            # Retrieve all the users subscriptions on stripe
            try:
                stripe_customer_subscriptions = stripe.Subscription.list(
                    customer=stripe_customer_id
                )["data"]
            except stripe._error.InvalidRequestError:
                # This is because the customer is either in test mode but live mode is running or
                # the customer is in live mode but test mode is running
                continue

            # If the organisation has no stripe subscription, then remove any subscription they may have in the database
            if (
                len(stripe_customer_subscriptions) == 0
                and organisation_subscription != "free"
            ):
                await db.remove_subscription(ref)
                continue

            elif len(stripe_customer_subscriptions) == 0:
                continue

            stripe_customer_subscription_names = [
                sub["plan"]["nickname"] for sub in stripe_customer_subscriptions
            ]

            new_subscription = stripe_customer_subscription_names[0]
            if organisation_subscription != new_subscription:
                await db.add_subscription(ref, new_subscription)

    except Exception as error:
        print(f"Error: {error}")
