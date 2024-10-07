import hashlib
import json
import jwt
import os
import requests
import time

from cryptography.hazmat.primitives import serialization
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

# Constants
PATH_TO_DATASET_DEFINITION_JSON = "./dataset_definition.json"
DATASET_ROOT_PATH = "../../../BloodSamples/MalariaDataset"
SERVICE_ROOT_PATH = "https://in.api.hemato.ai"

USE_THIS_AUTH_METHOD = "email" # accpeted values are keypair or email

# if the above is set to  "keypair", we are using public/private key, then ask for the values for the the following by contacting support@hemato.ai
AUTH_AUDIENCE = "dev.api.hemato.ai"
AUTH_ISSUER = "Miriam_Technologies_org_id"
KEY_ID = "vkzzmyxhli"
PRIVATE_KEY_FILE_PATH = "miriam_private.key"

# if USE_THIS_AUTH_METHOD is set to "email", we are using account / sesssion login, ask for the following values by contacting support@hemato.ai
USER_EMAIL = ""
USER_PASSOWRD = ""


@dataclass
class PBSPicture:
    path: str
    rbc_diameter: float = 0.0
    results: Dict[str, Any] = field(default_factory=dict)

@dataclass
class DatasetDefinition:
    id: str
    has_malaria: List[PBSPicture]
    no_malaria: List[PBSPicture]

@dataclass
class Result:
    timestamp: int = 0
    summary: List[Dict[str, List[float]]] = field(default_factory=list)



def hash_password(password: str) -> str:
    # Encode the password string to bytes
    password_bytes = password.encode('utf-8')

    # Calculate SHA256 hash
    hash_object = hashlib.sha256(password_bytes)

    # Get the hexadecimal representation
    hex_hash = hash_object.hexdigest()

    return hex_hash

def session_token_for_account(user_email: str, user_password: str) -> str:
    payload = {
        "user": user_email,
        "pass_hash": hash_password(user_password),
    }
    response = requests.post(
        f"{SERVICE_ROOT_PATH}/auth/login",
        json=payload
    )
    response.raise_for_status

    response = response.json()

    return response["results"]["token"]["HY_APP_AUTH_v1"]

def generate_auth_token(auth_audience: str, auth_issuer: str, key_id: str, private_key_path: str) -> str:
    with open(private_key_path, 'rb') as key_file:
        private_key = serialization.load_pem_private_key(
            key_file.read(),
            password=None
        )

    issued = datetime.utcnow()
    expiration = issued + timedelta(hours=1)

    payload = {
        'aud': [auth_audience],
        'exp': expiration,
        'iat': issued,
        'iss': auth_issuer,
        'jti': str(int(time.time() * 1e9)),
        'sub': 'test_subject',
        'kid': key_id
    }

    token = jwt.encode(
        payload,
        private_key,
        algorithm='RS256'
    )

    return token

def process(picture_full_path: str, rbc_diameter: float) -> Result:
    if USE_THIS_AUTH_METHOD == "keypair":
        auth_token = generate_auth_token(AUTH_AUDIENCE, AUTH_ISSUER, KEY_ID, PRIVATE_KEY_FILE_PATH)
    elif USE_THIS_AUTH_METHOD == "email":
        auth_token = session_token_for_account(USER_EMAIL, USER_PASSOWRD)
    else:
        raise Exception(f"This Auth Method is not supported '{USE_THIS_AUTH_METHOD}' either keypair or email are supported")

    results = Result()
    file_name = os.path.basename(picture_full_path)

    # Create a new study
    payload = {
        "purpose": "malaria_benchmark",
        "batch_id": str(int(time.time() * 1e9)),
        "local_file_name": file_name
    }

    response = requests.post(
        f"{SERVICE_ROOT_PATH}/pbs",
        json=payload,
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    response.raise_for_status()
    study_data = response.json()
    pbs_study_id = study_data['results']['pbs_study_id']

    print(f"StudyID {pbs_study_id}")


    # Upload the file
    with open(picture_full_path, 'rb') as file:
        params = {
            'file_name': file_name,
            'rbc_diameter': f"{rbc_diameter:.2f}"
        }

        file_content = file.read()

        response = requests.post(
            f"{SERVICE_ROOT_PATH}/pbs/{pbs_study_id}/files",
            data=file_content,
            params=params,
            headers={"Authorization": f"Bearer {auth_token}"}
        )
        response.raise_for_status()

    # Submit task
    task_payload = {
        "diagnostic_tasks": ["MALARIA_ANY_ANY"]
    }
    response = requests.post(
        f"{SERVICE_ROOT_PATH}/pbs/{pbs_study_id}/tasks",
        json=task_payload,
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    response.raise_for_status()

    # Wait for processing
    time.sleep(120)  # 2 minutes

    # Check results
    response = requests.get(
        f"{SERVICE_ROOT_PATH}/pbs/{pbs_study_id}/reports/MALARIA_ANY_ANY",
        headers={"Authorization": f"Bearer {auth_token}"}
    )
    response.raise_for_status()
    report_data = response.json()

    if report_data['results']['report']:
        results.timestamp = int(time.time() * 1e9)
        results.summary = report_data['results']['report']['MALARIA_ANY_ANY']['summary_reports']['model_findings']
    else:
        print(response.text)
        print(picture_full_path)

    return results

def main():
    print("let the fun begin!")

    try:
        with open(PATH_TO_DATASET_DEFINITION_JSON, 'r') as f:
            dataset_json = json.load(f)

        # Convert JSON to our dataclass
        dataset = DatasetDefinition(
            id=dataset_json['id'],
            has_malaria=[PBSPicture(**p) for p in dataset_json['has_malaria']],
            no_malaria=[PBSPicture(**p) for p in dataset_json['no_malaria']]
        )

        print(f"working on dataset {dataset.id}")

        # Process has_malaria pictures
        for idx, p in enumerate(dataset.has_malaria):
            picture_full_path = f"{DATASET_ROOT_PATH}/HasMalaria/{p.path}"
            if p.rbc_diameter == 0:
                print(f"NEEDS RBC SIZE: {picture_full_path}")
                continue

            try:
                res = process(picture_full_path, p.rbc_diameter)
                dataset.has_malaria[idx].results = vars(res)
            except Exception as e:
                print(f"error processing picture {picture_full_path}: {e}")

        # Process no_malaria pictures
        for idx, p in enumerate(dataset.no_malaria):
            picture_full_path = f"{DATASET_ROOT_PATH}/NoMalaria/{p.path}"
            if p.rbc_diameter == 0:
                print(f"NEEDS RBC SIZE {picture_full_path}")
                continue

            try:
                res = process(picture_full_path, p.rbc_diameter)
                dataset.no_malaria[idx].results = vars(res)
            except Exception as e:
                print(f"error processing picture {picture_full_path}: {e}")

    except Exception as e:
        print(f"Exeption happened {e}")

    finally:
        # Save results
        output_filename = f"./{int(time.time() * 1e9)}-dataset_definition.json"
        with open(output_filename, 'w') as f:
            json.dump(asdict(dataset), f, indent=2)

if __name__ == "__main__":
    main()