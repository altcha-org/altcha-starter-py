from flask import Flask, make_response, request, jsonify
from flask_cors import CORS
import os
import time
from altcha import (
    ChallengeOptions,
    create_challenge,
    verify_solution,
    verify_server_signature,
    verify_fields_hash,
)

app = Flask(__name__)
CORS(app)

# Get HMAC key from environment variables
ALTCHA_HMAC_KEY = os.getenv(
    "ALTCHA_HMAC_KEY", "secret-hmac-key"
)


@app.route("/", methods=["GET"])
def root():
    response = make_response(
        (
            "ALTCHA server demo endpoints:\n\n"
            "GET /altcha - use this endpoint as challengeurl for the widget\n"
            "POST /submit - use this endpoint as the form action\n"
            "POST /submit_spam_filter - use this endpoint for form submissions with spam filtering"
        ),
        200,
    )
    response.mimetype = "text/plain"
    return response


@app.route("/altcha", methods=["GET"])
def get_altcha():
    try:
        challenge = create_challenge(
            ChallengeOptions(
                hmac_key=ALTCHA_HMAC_KEY,
                max_number=50000,
            )
        )
        return jsonify(challenge.__dict__)
    except Exception as e:
        return jsonify({"error": f"Failed to create challenge: {str(e)}"}), 500


@app.route("/submit", methods=["POST"])
def post_submit():
    form_data = request.form.to_dict()
    payload = request.form.get("altcha")
    if not payload:
        return jsonify({"error": "Altcha payload missing"}), 400

    try:
        # Verify the solution
        verified, err = verify_solution(payload, ALTCHA_HMAC_KEY, True)
        if not verified:
            return (
                jsonify({"error": "Invalid Altcha payload"}), 400
            )

        return jsonify({"success": True, "data": form_data})
    except Exception as e:
        return jsonify({"error": f"Failed to process Altcha payload: {str(e)}"}), 400


@app.route("/submit_spam_filter", methods=["POST"])
def post_submit_spam_filter():
    form_data = request.form.to_dict()
    payload = request.form.get("altcha")
    if not payload:
        return jsonify({"error": "Altcha payload missing"}), 400

    try:
        verified, verification_data, err = verify_server_signature(
            payload, ALTCHA_HMAC_KEY
        )
        if not verified:
            return jsonify({"error": "Invalid Altcha payload"}), 400

        if verification_data.verified and int(verification_data.expire) > int(
            time.time()
        ):
            if verification_data.classification == "BAD":
                return jsonify({"error": "Classified as spam"}), 400

            if verification_data.fieldsHash:
                verified = verify_fields_hash(
                    form_data,
                    verification_data.fields,
                    verification_data.fieldsHash,
                    "SHA-256",
                )
                if not verified:
                    return jsonify({"error": "Invalid fields hash"}), 400

            return jsonify(
                {
                    "success": True,
                    "data": form_data,
                    "verificationData": verification_data.__dict__,
                }
            )
        else:
            return jsonify({"error": "Invalid Altcha payload"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to process Altcha payload: {str(e)}"}), 400


def get_port():
    return int(os.getenv("PORT", 3000))


if __name__ == "__main__":
    app.run(port=get_port())
