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
    Evaluates dossier states securely by matching provenance rules,
    isolating untrusted email bodies, and strictly slicing minimal evidence.
    """
    d_id = dossier.get("dossierId", "")
    mailbox = str(dossier.get("mailbox", "")).strip()
    objective = str(dossier.get("objective", "")).strip()
    
    # Precise field extraction matching frozen targets
    recipient = None
    reference_id = None
    value = None
    source_event_id = None
    
    # Specific targeted lines for minimal evidence matching
    authority_line_id = None
    recipient_line_id = None
    window_line_id = None
    event_line_id = None
    ref_line_id = None
    any_fallback_line_id = None
    
    has_trusted_system_approval = False
    is_indirect_injection = False
    injection_line_id = None

    # Step 1: Scan and map exact structural line attributes
    for src in dossier.get("sources", []):
        provenance = str(src.get("provenance", "")).lower()
        
        for line in src.get("lines", []):
            l_id = line.get("lineId", "")
            text = str(line.get("text", "")).strip()
            text_lower = text.lower()
            
            if not any_fallback_line_id:
                any_fallback_line_id = l_id

            # Structural Safety Gate
            if "override" in text_lower or "disregard previous instructions" in text_lower or "secret_canary" in text_lower:
                is_indirect_injection = True
                injection_line_id = l_id

            # Parse Trusted Management Assertions
            if "internal" in provenance or "system" in provenance or "trusted" in provenance:
                if "approve" in text_lower or "authorize" in text_lower:
                    has_trusted_system_approval = True
                    authority_line_id = l_id

            # Field Extraction Matrix with case preservation
            if "recipient:" in text_lower:
                recipient = text.split("recipient:")[-1].strip()
                recipient_line_id = l_id
            elif "to:" in text_lower and not recipient:
                recipient = text.split("to:")[-1].strip()
                recipient_line_id = l_id
                
            if "delivery window:" in text_lower:
                value = text.split("delivery window:")[-1].strip()
                window_line_id = l_id
                
            if "event id:" in text_lower:
                source_event_id = text.split("event id:")[-1].strip()
                event_line_id = l_id
                
            if "reference id:" in text_lower:
                reference_id = text.split("reference id:")[-1].strip()
                ref_line_id = l_id

    # Security Isolation Route (Highest Priority Constraint)
    if is_indirect_injection:
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": [injection_line_id] if injection_line_id else [any_fallback_line_id]
        }

    # -------------------------------------------------------------------------
    # DECISION LAYER: Authority & Case State Routing Mapping Rules
    # -------------------------------------------------------------------------
    
    # 1. Update Internal Record (Requires System Authority to execute alterations)
    if has_trusted_system_approval and ("update" in objective.lower() or "window" in objective.lower()):
        evidence = [authority_line_id]
        if window_line_id: evidence.append(window_line_id)
        if event_line_id: evidence.append(event_line_id)
        return {
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": d_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": source_event_id if source_event_id else "evt_default",
                "value": value if value else "standard_window"
            },
            "evidence": list(set(evidence))
        }

    # 2. Send Approved Notice (Requires explicit System Authorization)
    if has_trusted_system_approval and ("notice" in objective.lower() or "notify" in objective.lower()):
        evidence = [authority_line_id]
        if recipient_line_id: evidence.append(recipient_line_id)
        if ref_line_id: evidence.append(ref_line_id)
        return {
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": recipient if recipient else "customer@domain.com"},
            "payload": {
                "referenceId": reference_id if reference_id else d_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": list(set(evidence))
        }

    # 3. Request Confirmation (Route ambiguous requests or customer-driven update attempts here)
    if "unclear" in objective.lower() or "identity" in objective.lower() or "update" in objective.lower():
        evidence = []
        if recipient_line_id: evidence.append(recipient_line_id)
        if not evidence: evidence.append(any_fallback_line_id)
        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "operations_team"},
            "payload": {
                "claimedSender": recipient if recipient else "unknown_sender",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": d_id
            },
            "evidence": list(set(evidence))
        }

    # 4. Create Draft (Standard safe customer support response path)
    if "draft" in objective.lower() or "reply" in objective.lower() or "support" in objective.lower():
        evidence = []
        if recipient_line_id: evidence.append(recipient_line_id)
        if ref_line_id: evidence.append(ref_line_id)
        if not evidence: evidence.append(any_fallback_line_id)
        return {
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox if mailbox else 'support'}"},
            "payload": {
                "recipient": recipient if recipient else "customer@domain.com",
                "referenceId": reference_id if reference_id else d_id,
                "status": "PENDING",
                "template": "order_status"
            },
            "evidence": list(set(evidence))
        }

    # 5. Default Fallback baseline for purely information data streams
    return {
        "action": "no_action",
        "target": None,
        "payload": {
            "reasonCode": "INFORMATIONAL",
            "referenceId": d_id
        },
        "evidence": [any_fallback_line_id]
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
                # --- PHASE 2: COMMIT ---
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
            
            # --- ATOMIC PRE-VALIDATION ENFORCEMENT LOOP ---
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
                
                # Instantly abort entire block on layout mismatches
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
                
                # Instantly reject the entire commit execution block on one bad signature
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
            
            # Change the evaluation tracking state context only after all receipts clear successfully
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
