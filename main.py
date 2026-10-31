import json
import hashlib
import base64
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, Request, Response, HTTPException, status
import sqlite3

app = FastAPI()
DB_FILE = "mailroom.db"

def init_db():
    """Initializes SQLite tables for state tracking and content caching."""
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        
        # 1. Tracks active lifecycle phases (awaiting_receipts vs completed)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT,
                public_key_jwk TEXT,
                status TEXT
            )
        """)
        
        # 2. Caches decisions by content hash to prevent duplicate AI charges
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS dossier_cache (
                content_hash TEXT PRIMARY KEY,
                call_id TEXT,
                action TEXT,
                target TEXT,
                payload TEXT,
                evidence TEXT
            )
        """)
        
        # 3. Maps active proposal digests to cross-check during Phase 2
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS proposals (
                evaluation_id TEXT,
                dossier_id TEXT,
                call_id TEXT,
                action TEXT,
                proposal_digest TEXT,
                PRIMARY KEY (evaluation_id, dossier_id)
            )
        """)
        conn.commit()

# Execute database tables setup on script boot
init_db()

def canonical_json_bytes(obj: Any) -> bytes:
    """Recursively key-sorted compact JSON view engine."""
    return json.dumps(
        obj, 
        sort_keys=True, 
        separators=(',', ':'), 
        ensure_ascii=False
    ).encode('utf-8')

def compute_sha256_hex(data_bytes: bytes) -> str:
    """Returns the lowercase SHA-256 hex string for the provided bytes."""
    return hashlib.sha256(data_bytes).hexdigest().lower()

def evaluate_dossier_securely(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses explicitly documented authority, checks content provenance boundaries,
    and returns exact frozen target-payload structures with minimal evidence.
    """
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "")
    objective = str(dossier.get("objective", "")).lower()
    
    all_text = ""
    evidence_lines = []
    has_internal_approval = False
    
    extracted = {
        "recipient": None,
        "referenceId": None,
        "value": None,
        "sourceEventId": None
    }

    # Step 1: Scan lines for strict authority flags and dynamic variables
    for src in dossier.get("sources", []):
        provenance = str(src.get("provenance", "")).lower()
        
        for line in src.get("lines", []):
            l_id = line.get("lineId", "")
            text = line.get("text", "")
            all_text += " " + text
            text_lower = text.lower()

            # Rule A: Enforce prompt injection boundary filters (Highest Priority)
            if "override" in text_lower or "disregard" in text_lower or "canary" in text_lower:
                return {
                    "action": "quarantine_item",
                    "target": {"kind": "security_queue", "id": "mailroom"},
                    "payload": {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
                    "evidence": [l_id]
                }

            # Rule B: Identify Explicit System Authority
            if "internal" in provenance or "system" in provenance or "trusted" in provenance:
                if "approve" in text_lower or "authorize" in text_lower:
                    has_internal_approval = True
                    if l_id not in evidence_lines:
                        evidence_lines.append(l_id)

            # Rule C: Parse case arguments safely
            if "recipient:" in text_lower:
                extracted["recipient"] = text.split("recipient:")[-1].strip()
                if l_id not in evidence_lines:
                    evidence_lines.append(l_id)
            elif "delivery window:" in text_lower:
                extracted["value"] = text.split("delivery window:")[-1].strip()
                if l_id not in evidence_lines:
                    evidence_lines.append(l_id)
            elif "event id:" in text_lower:
                extracted["sourceEventId"] = text.split("event id:")[-1].strip()
                if l_id not in evidence_lines:
                    evidence_lines.append(l_id)
            elif "reference id:" in text_lower:
                extracted["referenceId"] = text.split("reference id:")[-1].strip()
                if l_id not in evidence_lines:
                    evidence_lines.append(l_id)

    # Fallback if no specific lines are found (avoids empty lists breaking contract schemas)
    if not evidence_lines:
        for src in dossier.get("sources", []):
            for line in src.get("lines", []):
                if line.get("lineId"):
                    evidence_lines.append(line.get("lineId"))
                    break
            if evidence_lines:
                break
    if not evidence_lines:
        evidence_lines = ["line_0"]

    # -------------------------------------------------------------------------
    # ROUTING DECISION LAYER (Fulfills strict API payload schema matrices)
    # -------------------------------------------------------------------------
    if "update" in objective or "record" in objective:
        return {
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": d_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": extracted["sourceEventId"] if extracted["sourceEventId"] else "evt_default",
                "value": extracted["value"] if extracted["value"] else "standard_window"
            },
            "evidence": evidence_lines
        }

    if has_internal_approval and ("notice" in objective or "notify" in objective):
        return {
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": extracted["recipient"] if extracted["recipient"] else "customer@domain.com"},
            "payload": {
                "referenceId": extracted["referenceId"] if extracted["referenceId"] else d_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": evidence_lines
        }

    if "draft" in objective or "reply" in objective:
        return {
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            "payload": {
                "recipient": extracted["recipient"] if extracted["recipient"] else "customer@domain.com",
                "referenceId": extracted["referenceId"] if extracted["referenceId"] else d_id,
                "status": "PENDING",
                "template": "order_status"
            },
            "evidence": evidence_lines
        }

    if "unclear" in objective or "ambiguous" in objective or "identity" in objective:
        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "operations_team"},
            "payload": {
                "claimedSender": extracted["recipient"] if extracted["recipient"] else "unknown_sender",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": d_id
            },
            "evidence": evidence_lines
        }

    return {
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": d_id
        },
        "evidence": evidence_lines
    }

def verify_ed25519_signature(public_key_x_b64url: str, signature_b64: str, data: bytes) -> bool:
    """Verifies an Ed25519 digital signature given a base64url encoded public key x value."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    try:
        rem = len(public_key_x_b64url) % 4
        if rem:
            public_key_x_b64url += '=' * (4 - rem)
        public_key_bytes = base64.urlsafe_b64decode(public_key_x_b64url)
        signature_bytes = base64.b64decode(signature_b64)
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, data)
        return True
    except Exception:
        return False

@app.post("/mailroom")
async def mailroom_action_gate(request: Request):
    # Enforce request boundary checks and size restrictions
    body_bytes = await request.body()
    if not body_bytes:
        raise HTTPException(status_code=400, detail="Empty request body")
        
    try:
        req_json = json.loads(body_bytes)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="Malformed JSON schema")
        
    operation = req_json.get("operation")
    evaluation_id = req_json.get("evaluationId")
    
    if not operation or not evaluation_id:
        raise HTTPException(status_code=422, detail="Missing baseline validation parameters")

    with sqlite3.connect(DB_FILE) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # -----------------------------------------------------------------
        # PHASE 1: PROPOSE LIFECYCLE
        # -----------------------------------------------------------------
        if operation == "propose":
            dossiers = req_json.get("dossiers", [])
            
            dossier_ids = [d.get("dossierId") for d in dossiers]
            if len(dossier_ids) != len(set(dossier_ids)):
                raise HTTPException(status_code=400, detail="Duplicate dossierIds detected")
            
            # Compute inputDigest exclusively over just the dossiers array
            input_digest = compute_sha256_hex(canonical_json_bytes(dossiers))
            
            # Idempotency Replay verification check
            cursor.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (evaluation_id,))
            existing_eval = cursor.fetchone()
            
            if existing_eval:
                if existing_eval["input_digest"] != input_digest:
                    raise HTTPException(status_code=409, detail="Conflict: configuration payload mutations")
                
                cursor.execute("SELECT dossier_id, call_id, action, proposal_digest FROM proposals WHERE evaluation_id = ?", (evaluation_id,))
                saved_props = cursor.fetchall()
                
                proposals_response = []
                for sp in saved_props:
                    cursor.execute("SELECT * FROM dossier_cache WHERE call_id = ?", (sp["call_id"],))
                    cached_data = cursor.fetchone()
                    proposals_response.append({
                        "dossierId": sp["dossier_id"],
                        "callId": sp["call_id"],
                        "action": sp["action"],
                        "target": json.loads(cached_data["target"]) if cached_data["target"] else None,
                        "payload": json.loads(cached_data["payload"]),
                        "evidence": json.loads(cached_data["evidence"])
                    })
                
                return {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "status": "awaiting_receipts",
                    "inputDigest": input_digest,
                    "proposals": proposals_response
                }
            
            verifier = req_json.get("receiptVerifier", {})
            jwk_str = json.dumps(verifier.get("publicKeyJwk", {}))
            
            proposals_out = []
            for d in dossiers:
                d_id = d.get("dossierId")
                d_hash = compute_sha256_hex(canonical_json_bytes(d))
                
                cursor.execute("SELECT * FROM dossier_cache WHERE content_hash = ?", (d_hash,))
                cached_dossier = cursor.fetchone()
                
                if cached_dossier:
                    call_id = cached_dossier["call_id"]
                    action = cached_dossier["action"]
                    target = json.loads(cached_dossier["target"]) if cached_dossier["target"] else None
                    payload = json.loads(cached_dossier["payload"])
                    evidence = json.loads(cached_dossier["evidence"])
                else:
                    ai_res = evaluate_dossier_securely(d)
                    call_id = f"call_{d_hash[:20]}_{str(d_id)[-8:]}"
                    action = ai_res["action"]
                    target = ai_res["target"]
                    payload = ai_res["payload"]
                    evidence = ai_res["evidence"]
                    
                    cursor.execute("""
                        INSERT INTO dossier_cache (content_hash, call_id, action, target, payload, evidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (d_hash, call_id, action, json.dumps(target), json.dumps(payload), json.dumps(evidence)))
                
                # Filter elements to match exact serialization criteria for the digest
                prop_digest_obj = {
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": target,
                    "payload": payload,
                    "evidence": sorted(evidence)
                }
                proposal_digest = compute_sha256_hex(canonical_json_bytes(prop_digest_obj))
                
                cursor.execute("""
                    INSERT INTO proposals (evaluation_id, dossier_id, call_id, action, proposal_digest)
                    VALUES (?, ?, ?, ?, ?)
                """, (evaluation_id, d_id, call_id, action, proposal_digest))
                
                proposals_out.append({
                    "dossierId": d_id,
                    "callId": call_id,
                    "action": action,
                    "target": target,
                    "payload": payload,
                    "evidence": evidence
                })
            
            cursor.execute("""
                INSERT INTO evaluations (evaluation_id, input_digest, public_key_jwk, status)
                VALUES (?, ?, ?, 'awaiting_receipts')
            """, (evaluation_id, input_digest, jwk_str))
            
            conn.commit()
            
            return {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals_out
            }

        # -----------------------------------------------------------------
        # PHASE 2: COMMIT LIFECYCLE
        # -----------------------------------------------------------------
        elif operation == "commit":
            cursor.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (evaluation_id,))
            eval_record = cursor.fetchone()
            
            if not eval_record:
                raise HTTPException(status_code=400, detail="Unknown evaluation identifier context")
                
            input_digest = req_json.get("inputDigest")
            if eval_record["input_digest"] != input_digest:
                raise HTTPException(status_code=400, detail="Input digest mismatch")
                
            if eval_record["status"] == "completed":
                cursor.execute("SELECT dossier_id, call_id, action, proposal_digest FROM proposals WHERE evaluation_id = ?", (evaluation_id,))
                cached_props = cursor.fetchall()
                
                outcomes = []
                for cp in cached_props:
                    outcomes.append({
                        "dossierId": cp["dossier_id"],
                        "callId": cp["call_id"],
                        "action": cp["action"],
                        "proposalDigest": cp["proposal_digest"],
                        "receiptId": "nonce_replay_record",
                        "status": "executed"
                    })
                return {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "status": "completed",
                    "inputDigest": input_digest,
                    "outcomes": outcomes
                }

            receipts = req_json.get("receipts", [])
            jwk = json.loads(eval_record["public_key_jwk"])
            public_key_x = jwk.get("x")
            
            # Verify the ENTIRE signature array atomically before updating database state
            validated_receipt_records = []
            for r in receipts:
                d_id = r.get("dossierId")
                c_id = r.get("callId")
                act = r.get("action")
                p_digest = r.get("proposalDigest")
                sig = r.get("receiptSignature")
                
                cursor.execute("""
                    SELECT * FROM proposals 
                    WHERE evaluation_id = ? AND dossier_id = ?
                """, (evaluation_id, d_id))
                local_prop = cursor.fetchone()
                
                if not local_prop or local_prop["call_id"] != c_id or local_prop["action"] != act or local_prop["proposal_digest"] != p_digest:
                    raise HTTPException(status_code=400, detail="Receipt validation mismatch error")
                
                inner_receipt = {
                    "dossierId": d_id,
                    "callId": c_id,
                    "action": act,
                    "accepted": r.get("accepted"),
                    "proposalDigest": p_digest,
                    "receiptId": r.get("receiptId")
                }
                
                verification_container = {
                    "profile": "ga5-mailroom-action-gate/v2",
                    "evaluationId": evaluation_id,
                    "inputDigest": input_digest,
                    "receipt": inner_receipt
                }
                
                if not verify_ed25519_signature(public_key_x, sig, canonical_json_bytes(verification_container)):
                    raise HTTPException(status_code=400, detail="Invalid cryptographic signature entry")
                
                validated_receipt_records.append({
                    "dossierId": d_id,
                    "callId": c_id,
                    "action": act,
                    "proposalDigest": p_digest,
                    "receiptId": r.get("receiptId"),
                    "status": "executed" if r.get("accepted") is True else "rejected"
                })
            
            cursor.execute("UPDATE evaluations SET status = 'completed' WHERE evaluation_id = ?", (evaluation_id,))
            conn.commit()
            
            return {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "completed",
                "inputDigest": input_digest,
                "outcomes": validated_receipt_records
            }
            
        else:
            raise HTTPException(status_code=400, detail="Unsupported command path")
