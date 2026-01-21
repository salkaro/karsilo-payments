# Local Imports


# External Imports
from google.cloud.firestore_v1.async_client import AsyncClient
from google.cloud.firestore_v1 import AsyncDocumentReference
from google.oauth2 import service_account
from google.cloud import firestore
from dotenv import load_dotenv

import traceback
import os

load_dotenv()


class Database:
    # Class-level attributes for environment variables
    FIREBASE_PROJECT_ID = os.getenv("FIREBASE_PROJECT_ID")
    FIREBASE_PRIVATE_KEY_ID = os.getenv("FIREBASE_PRIVATE_KEY_ID")
    _raw_private_key = os.getenv("FIREBASE_PRIVATE_KEY")
    FIREBASE_PRIVATE_KEY = _raw_private_key.replace("\\n", "\n") if _raw_private_key else None
    FIREBASE_CLIENT_EMAIL = os.getenv("FIREBASE_CLIENT_EMAIL")
    FIREBASE_CLIENT_ID = os.getenv("FIREBASE_CLIENT_ID")
    FIREBASE_CLIENT_X509_CERT_URL = os.getenv("FIREBASE_CLIENT_X509_CERT_URL")
    FIREBASE_PROJECT_URL = os.getenv("FIREBASE_PROJECT_URL")

    # A flag to track initialization
    _initialized = False
    _firebase_credentials = None

    def __init__(self):
        if not Database._initialized:
            # Credentials for service account
            Database._firebase_credentials = service_account.Credentials.from_service_account_info(
                {
                    "type": "service_account",
                    "project_id": Database.FIREBASE_PROJECT_ID,
                    "private_key_id": Database.FIREBASE_PRIVATE_KEY_ID,
                    "private_key": Database.FIREBASE_PRIVATE_KEY,
                    "client_email": Database.FIREBASE_CLIENT_EMAIL,
                    "client_id": Database.FIREBASE_CLIENT_ID,
                    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "auth_provider_x509_cert_url": "https://www.googleapis.com/oauth2/v1/certs",
                    "client_x509_cert_url": Database.FIREBASE_CLIENT_X509_CERT_URL,
                    "universe_domain": "googleapis.com",
                }
            )

            # Mark as initialized
            Database._initialized = True

    async def get_db_client(self) -> AsyncClient:
        return AsyncClient(
            project=Database.FIREBASE_PROJECT_ID,
            credentials=Database._firebase_credentials,
        )

    async def query_organisation_stream(self):
        try:
            db: AsyncClient = await self.get_db_client()
            # Query and get matching documents
            query_ref = db.collection("organisations")
            return query_ref.stream()

        except Exception as error:
            print(f"An error occurred in query_organisation_stream(): {error}")
            print(traceback.format_exc())

    async def query_organisations_ref(
        self, key, value
    ) -> AsyncDocumentReference | None:
        try:
            db: AsyncClient = await self.get_db_client()
            # Query and get matching documents
            query_ref = db.collection("organisations").where(key, "==", value)
            results = query_ref.stream()

            # Return the document reference of the first match
            async for doc in results:
                return db.document(doc.reference.path)

        except Exception as error:
            print(f"An error occurred in query_user_ref(): {error}")
            print(traceback.format_exc())

    async def add_subscription(self, ref: AsyncDocumentReference, subscription: str):
        try:
            # Step 1: If the subscription to add is new, then add it
            await ref.update({"subscription": subscription})

        except Exception as error:
            print(f"An error occurred in add_subscription(): {error}")
            print(traceback.format_exc())

    async def remove_subscription(self, ref: AsyncDocumentReference):
        try:
            # Step 1: Update document subscription to free
            await ref.update({"subscription": "free"})

        except Exception as error:
            print(f"An error occurred in remove_subscription(): {error}")
            print(traceback.format_exc())
