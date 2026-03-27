from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()
import os
print("DEBUG - Key loaded:", os.getenv("AZURE_OPENAI_KEY") is not None)
print("DEBUG - Endpoint loaded:", os.getenv("AZURE_OPENAI_ENDPOINT"))

endpoint = os.getenv("AZURE_OPENAI_ENDPOINT")
model_name = "gpt-5.3-chat"
deployment = os.getenv("AZURE_OPENAI_DEPLOYMENT")

subscription_key =  os.getenv("AZURE_OPENAI_KEY")
api_version = os.getenv("AZURE_OPENAI_API_VERSION")

client = AzureOpenAI(
    api_version=api_version,
    azure_endpoint=endpoint,
    api_key=subscription_key,
)
print("DEBUG - Using deployment:", deployment)
print("DEBUG - Using endpoint:", endpoint)


print("Endpoint:", endpoint)
print("Deployment:", deployment)
print("API Version:", api_version)
print("Key starts with:", subscription_key[:10] if subscription_key else "NOT SET")
response = client.chat.completions.create(
    messages=[
        {
            "role": "system",
            "content": "You are a helpful assistant.",
        },
        {
            "role": "user",
            "content": "I am going to Paris, what should I see?",
        }
    ],
    max_completion_tokens =16384,
    model=deployment
)

print(response.choices[0].message.content)