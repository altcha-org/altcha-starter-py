# ALTCHA Server Demo for Python

This repository demonstrates the implementation of an ALTCHA server with spam filtering using the [altcha](https://github.com/altcha-org/altcha) Python library. The server provides endpoints for fetching challenges and submitting form data, including verification of Proof-of-Work (PoW) solutions and spam filtering.

## Documentation

- [Server Integration](https://altcha.org/docs/server-integration/)
- [Spam Filter payload verification](https://altcha.org/docs/api/challenge-api/#server-verification)

## Requirements

- Python 3.8 or later

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/altcha-org/altcha-starter-py.git
    cd altcha-starter-py
    ```

2. Set up a virtual environment and install dependencies:

    ```sh
    python3 -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    ```

## Configuration

The server requires the following environment variables for configuration:

- `ALTCHA_HMAC_KEY`: Secret key used for HMAC in ALTCHA challenge generation (optional, generated if not provided).

You can create a `.env` file in the root directory to set these environment variables:

```ini
PORT=3000
ALTCHA_HMAC_KEY=your_custom_hmac_key
```

## Modes of Operation

- **Self-Hosted**: In fully self-hosted mode, configure your `ALTCHA_HMAC_KEY` (a secure randomly generated key) and utilize the `GET /altcha` as a `challengeurl` and the `POST /submit` endpoint as the form's `action`.
- **ALTCHA API without Spam Filter**: Configure ALTCHA's API URL as `challengeurl` and the `POST /submit` endpoint as the form's `action`. Configure your API Key's secret as `ALTCHA_HMAC_KEY` (e.g., `ALTCHA_HMAC_KEY=csec_...`).
- **ALTCHA API with Spam Filter**: Configure ALTCHA's API URL as `challengeurl` and the `POST /submit_spam_filter` endpoint as the form's `action`. Configure your API Key's secret as `ALTCHA_HMAC_KEY` (e.g., `ALTCHA_HMAC_KEY=csec_...`).

## Verification Methods

The `VerifySolution` function is used when verifying a simple Proof-of-Work (PoW) challenge. This is the standard verification method when the **Spam Filter is NOT enabled** on the ALTCHA widget.

The `VerifyServerSignature` function is used when the **Spam Filter is enabled** on the ALTCHA widget. When the Spam Filter is active, the format of the altcha payload changes, and additional verification steps are required to ensure the submission is not spam.

The `VerifyFieldsHash` function is used to verify the field values using the `fieldsHash` property from the verification data. It validates that the values of the fields have not changed since the Spam Filter classified the fields.

## Usage

To start the server, run:

```sh
python app.py
```

The server will be running on the port specified in the configuration (default is 3000).

## Endpoints

### GET /altcha

Fetches a new random challenge to be used by the ALTCHA widget.

- **URL:** `/altcha`
- **Method:** `GET`
- **Response:** JSON object containing the challenge.

#### Example

```sh
curl http://localhost:3000/altcha
```

### POST /submit

Submits form data and verifies the simple PoW challenge without the spam filter.

- **URL:** `/submit`
- **Method:** `POST`
- **Form Data:**
  - `altcha`: ALTCHA verification payload.

#### Example

```sh
curl -X POST -F 'altcha=your_verification_payload' http://localhost:3000/submit
```

### POST /submit_spam_filter

Submits form data and verifies the server signature generated by the spam filter.

- **URL:** `/submit_spam_filter`
- **Method:** `POST`
- **Form Data:**
  - `altcha`: ALTCHA verification payload.

#### Example

```sh
curl -X POST -F 'altcha=your_verification_payload' http://localhost:3000/submit_spam_filter
```

## License

MIT