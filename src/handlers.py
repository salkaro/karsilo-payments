# Local Imports
from src.database import Database

# External Imports
from fastapi.responses import JSONResponse

import traceback
import stripe


async def handle_subscription_update(
    db: Database, stripe_customer_id: str, price_id: str, product_id: str
):
    try:
        # Step 1: Query organisation ref
        ref = await db.query_organisations_ref("stripeCustomerId", stripe_customer_id)
        if ref is None:
            print(f"Organisation not found. Customer ID: {stripe_customer_id}")
            return JSONResponse(
                content={
                    "message": f"Organisation not found. Customer ID: {stripe_customer_id}"
                },
                status_code=404,
            )

        # Step 2: Retrieve stripe price name
        price = stripe.Price.retrieve(price_id)
        name = price.get("nickname")

        # Step 3: Update users subscription
        await db.add_subscription(ref, name)

        print(f"Subscription active, added {product_id} to {stripe_customer_id}")
        return JSONResponse(
            content={
                "message": f"Subscription inactive, removed {product_id} from {stripe_customer_id}",
                "customer": stripe_customer_id,
            },
            status_code=200,
        )

    except Exception as e:
        print(f"An error occured in handle_subscription_update(): {e}")
        print(traceback.format_exc())
        return JSONResponse(
            content={"message": "An error occured in handle_subscription_update()"},
            status_code=500,
        )


async def handle_subscription_deletion(
    db: Database, stripe_customer_id: str, product_id: str
):
    try:
        # Step 1: Query organisation ref
        ref = await db.query_organisations_ref("stripeCustomerId", stripe_customer_id)
        if ref is None:
            print(f"Organisation not found. Customer ID: {stripe_customer_id}")
            return JSONResponse(
                content={
                    "message": f"Organisation not found. Customer ID: {stripe_customer_id}"
                },
                status_code=404,
            )

        # Step 2: Remove user subscription
        await db.remove_subscription(ref)

        print(f"Subscription inactive, removed {product_id} from {stripe_customer_id}")
        return JSONResponse(
            content={
                "message": f"Subscription inactive, removed {product_id} from {stripe_customer_id}",
                "customer": stripe_customer_id,
            },
            status_code=200,
        )

    except Exception as error:
        print(f"An error occurred in handle_subscription_deletion(): {error}")
        print(traceback.format_exc())
        return JSONResponse(
            content={
                "message": "An error occurred while processing the subscription deletion",
                "error": str(error),
            },
            status_code=500,
        )
