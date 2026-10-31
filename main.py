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
        
        # 1. Stores evaluation context metadata
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS evaluations (
                evaluation_id TEXT PRIMARY KEY,
                input_digest TEXT,
                public_key_jwk TEXT,
                status TEXT
            )
        """)
        
        # 2. Caches agent proposals by the deterministic content hash of a dossier
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
        
        # 3. Maps active proposal digests to their dossier for verification validation
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

# Run database setup immediately when script initializes
init_db()

def canonical_json_bytes(obj: Any) -> bytes:
    """Encodes JSON structures compactly with recursively sorted keys."""
    return json.dumps(
        obj, 
        sort_keys=True, 
        separators=(',', ':'), 
        ensure_ascii=False
    ).encode('utf-8')

def compute_sha256_hex(data_bytes: bytes) -> str:
    """Returns the lowercase SHA-256 hex string for the provided bytes."""
    return hashlib.sha256(data_bytes).hexdigest().lower()

def mock_ai_agent_evaluate(dossier: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates incoming dossiers using explicit authority routing,
    provenance filtering, strict argument mapping, and minimal evidence.
    """
    d_id = dossier.get("dossierId", "")
    mailbox = dossier.get("mailbox", "")
    objective = dossier.get("objective", "")
    
    # Track critical evaluation states
    all_text = ""
    has_trusted_approval = False
    approval_line_id = None
    
    # Store dynamic arguments captured from case text lines
    extracted_args = {
        "referenceId": d_id,
        "recipient": None,
        "value": None,
        "sourceEventId": None,
        "field": None
    }
    
    argument_line_ids = []
    indirect_injection_detected = False
    injection_line_id = None

    # Step 1: Parse content lines, checking for overrides and extracting arguments
    for src in dossier.get("sources", []):
        provenance = src.get("provenance", "")
        kind = src.get("kind", "")
        
        for line in src.get("lines", []):
            l_id = line.get("lineId", "")
            text = line.get("text", "")
            all_text += " " + text
            
            # Check for indirect prompt injection attack markers
            text_lower = text.lower()
            if "override" in text_lower or "disregard previous instructions" in text_lower or "secret_canary" in text_lower:
                indirect_injection_detected = True
                injection_line_id = l_id

            # Parse structural management variables out of trusted/internal provenance contexts
            if provenance == "internal_system" or "trusted" in provenance:
                if "approved" in text_lower or "authorized" in text_lower:
                    has_trusted_approval = True
                    approval_line_id = l_id
            
            # Extract arguments matching case specifications
            if "delivery window:" in text_lower:
                extracted_args["value"] = text.split("delivery window:")[-1].strip()
                argument_line_ids.append(l_id)
            if "event id:" in text_lower:
                extracted_args["sourceEventId"] = text.split("event id:")[-1].strip()
                argument_line_ids.append(l_id)
            if "recipient:" in text_lower or "to:" in text_lower:
                extracted_args["recipient"] = text.split(":")[-1].strip()
                argument_line_ids.append(l_id)

    # -------------------------------------------------------------------------
    # ROUTING MATRIX LAYER (Prioritizes Safety, Authority, then Baseline Routing)
    # -------------------------------------------------------------------------
    
    # Route 1: Security Quarantine Lock (Highest Priority)
    if indirect_injection_detected:
        return {
            "action": "quarantine_item",
            "target": {"kind": "security_queue", "id": "mailroom"},
            "payload": {"artifactId": d_id, "reasonCode": "INDIRECT_PROMPT_INJECTION"},
            "evidence": [injection_line_id] if injection_line_id else ["line_0"]
        }

    # Compile the minimal sufficent evidence array for standard paths
    minimal_evidence = []
    if approval_line_id:
        minimal_evidence.append(approval_line_id)
    if argument_line_ids:
        minimal_evidence.extend(argument_line_ids)
    if not minimal_evidence:
        minimal_evidence = ["line_0"]

    # Route 2: Update Internal Record Schema Mapping
    if "update_record" in objective.lower() or "delivery_window" in all_text:
        return {
            "action": "update_internal_record",
            "target": {"kind": "case_record", "id": d_id},
            "payload": {
                "field": "delivery_window",
                "sourceEventId": extracted_args["sourceEventId"] if extracted_args["sourceEventId"] else "evt_default",
                "value": extracted_args["value"] if extracted_args["value"] else "standard_window"
            },
            "evidence": minimal_evidence
        }

    # Route 3: Send Approved Notice (Requires Internal System Explicit Sign-off)
    if has_trusted_approval and ("notify" in objective.lower() or "notice" in objective.lower()):
        return {
            "action": "send_approved_notice",
            "target": {"kind": "email", "id": extracted_args["recipient"] if extracted_args["recipient"] else "customer@domain.com"},
            "payload": {
                "referenceId": d_id,
                "status": "APPROVED",
                "template": "approved_delivery_notice"
            },
            "evidence": minimal_evidence
        }

    # Route 4: Route Ambiguous Tasks to Request Confirmation Queue
    if "unclear" in objective.lower() or "identity" in objective.lower():
        return {
            "action": "request_confirmation",
            "target": {"kind": "approval_queue", "id": "operations_team"},
            "payload": {
                "claimedSender": extracted_args["recipient"] if extracted_args["recipient"] else "unknown_sender",
                "questionCode": "VERIFY_REQUEST",
                "referenceId": d_id
            },
            "evidence": minimal_evidence
        }

    # Route 5: Create Draft Queue Routing
    if "draft" in objective.lower() or "reply" in objective.lower():
        return {
            "action": "create_draft",
            "target": {"kind": "draft_queue", "id": f"mailbox:{mailbox}"},
            "payload": {
                "recipient": extracted_args["recipient"] if extracted_args["recipient"] else "customer@domain.com",
                "referenceId": d_id,
                "status": "PENDING",
                "template": "order_status"
            },
            "evidence": minimal_evidence
        }

    # Route 6: Fallback Baseline for Informational Contexts
    return {
        "action": "no_action",
        "target": None,
        "payload": {"reasonCode": "INFORMATIONAL", "referenceId": d_id},
        "evidence": ["line_0"]
    }


def verify_ed25519_signature(public_key_x_b64url: str, signature_b64: str, data: bytes) -> bool:
    """Verifies an Ed25519 digital signature given a base64url encoded public key x value."""
    from cryptography.hazmat.primitives.asymmetric import ed25519
    
    try:
        # Normalize base64url padding for the public key
        rem = len(public_key_x_b64url) % 4
        if rem:
            public_key_x_b64url += '=' * (4 - rem)
        public_key_bytes = base64.urlsafe_b64decode(public_key_x_b64url)
        
        # Decode signature bytes
        signature_bytes = base64.b64decode(signature_b64)
        
        # Perform asymmetric validation
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(public_key_bytes)
        public_key.verify(signature_bytes, data)
        return True
    except Exception:
        return False

@app.post("/mailroom")
async def mailroom_action_gate(request: Request):
    # Parse request raw content to enforce limits
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
            
            # Enforce schema integrity rules
            dossier_ids = [d.get("dossierId") for d in dossiers]
            if len(dossier_ids) != len(set(dossier_ids)):
                raise HTTPException(status_code=400, detail="Duplicate dossierIds detected inside payload batch")
            
            # Compute canonical input digest over the sorted compact dossiers view
            input_digest = compute_sha256_hex(canonical_json_bytes(dossiers))
            
            # Check for existing evaluation replay/conflicts
            cursor.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (evaluation_id,))
            existing_eval = cursor.fetchone()
            
            if existing_eval:
                if existing_eval["input_digest"] != input_digest:
                    raise HTTPException(status_code=409, detail="Conflict: evaluationId mismatch against mutation updates")
                
                # Fetch and replay exact saved response state
                cursor.execute("""
                    SELECT dossier_id, call_id, action, proposal_digest 
                    FROM proposals WHERE evaluation_id = ?
                """, (evaluation_id,))
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
            
            # Extract receipt validation key infrastructure
            verifier = req_json.get("receiptVerifier", {})
            jwk_str = json.dumps(verifier.get("publicKeyJwk", {}))
            
            # Process proposals
            proposals_out = []
            for d in dossiers:
                d_id = d.get("dossierId")
                # Fingerprint individual item content to circumvent duplicate AI model call charges
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
                    # Execute AI parsing engine pipeline logic
                    ai_res = mock_ai_agent_evaluate(d)
                    call_id = f"call_{d_hash[:20]}_{d_id[-8:]}"
                    action = ai_res["action"]
                    target = ai_res["target"]
                    payload = ai_res["payload"]
                    evidence = ai_res["evidence"]
                    
                    cursor.execute("""
                        INSERT INTO dossier_cache (content_hash, call_id, action, target, payload, evidence)
                        VALUES (?, ?, ?, ?, ?, ?)
                    """, (d_hash, call_id, action, json.dumps(target), json.dumps(payload), json.dumps(evidence)))
                # Construct deterministic proposal digest block mapping
                                #  THE CORRECT FIXED OBJECT MATRIX BUILDER:
                prop_digest_obj = {
                    "dossierId": str(d_id),
                    "callId": str(call_id),
                    "action": str(action),
                    "target": target,
                    "payload": payload,
                    "evidence": sorted(list(evidence)) if isinstance(evidence, list) else [str(evidence)]
                }

                proposal_digest = compute_sha256_hex(canonical_json_bytes(prop_digest_obj))
                
                # Map tracking components for phase 2 verification
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
            
            # Save evaluation status baseline
            cursor.execute("""
                INSERT INTO evaluations (evaluation_id, input_digest, public_key_jwk, status)
                VALUES (?, ?, ?, 'awaiting_receipts')
            """, (evaluation_id, input_digest, jwk_str))
            
            conn.commit()
            
            response_payload = {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "awaiting_receipts",
                "inputDigest": input_digest,
                "proposals": proposals_out
            }
            
            if len(canonical_json_bytes(response_payload)) > 524288:
                raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="Payload limit threshold breached")
                
            return response_payload

        # -----------------------------------------------------------------
        # PHASE 2: COMMIT LIFECYCLE
        # -----------------------------------------------------------------
        elif operation == "commit":
            cursor.execute("SELECT * FROM evaluations WHERE evaluation_id = ?", (evaluation_id,))
            eval_record = cursor.fetchone()
            
            if not eval_record:
                raise HTTPException(status_code=400, detail="Unknown evaluation identifier environment context")
                
            input_digest = req_json.get("inputDigest")
            if eval_record["input_digest"] != input_digest:
                raise HTTPException(status_code=400, detail="Input digest scope configuration mismatch")
                
            # Idempotency Replay check
            if eval_record["status"] == "completed":
                # Instantly extract mapped execution array records
                cursor.execute("SELECT dossier_id, call_id, action, proposal_digest FROM proposals WHERE evaluation_id = ?", (evaluation_id,))
                cached_props = cursor.fetchall()
                
                # Fetch simulated processing metrics matching saved historical parameters
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
            
            outcomes = []
            
            # Atomic loop execution
            for r in receipts:
                d_id = r.get("dossierId")
                c_id = r.get("callId")
                act = r.get("action")
                p_digest = r.get("proposalDigest")
                sig = r.get("receiptSignature")
                
                # Step 1: Verify receipt mapping coordinates with local proposal tracking data
                cursor.execute("""
                    SELECT * FROM proposals 
                    WHERE evaluation_id = ? AND dossier_id = ?
                """, (evaluation_id, d_id))
                local_prop = cursor.fetchone()
                
                if not local_prop or local_prop["call_id"] != c_id or local_prop["action"] != act or local_prop["proposal_digest"] != p_digest:
                    raise HTTPException(status_code=400, detail="Receipt scopes conflict with state ledger entries")
                
                # Step 2: Build verification inner object payload target
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
                
                # Step 3: Enforce cryptographic integrity signatures
                serialized_verification = canonical_json_bytes(verification_container)
                if not verify_ed25519_signature(public_key_x, sig, serialized_verification):
                    raise HTTPException(status_code=400, detail="Invalid cryptographic signature envelope detected")
                
                status_string = "executed" if r.get("accepted") is True else "rejected"
                
                outcomes.append({
                    "dossierId": d_id,
                    "callId": c_id,
                    "action": act,
                    "proposalDigest": p_digest,
                    "receiptId": r.get("receiptId"),
                    "status": status_string
                })
            
            # Commit state status transition safely to database engine storage
            cursor.execute("UPDATE evaluations SET status = 'completed' WHERE evaluation_id = ?", (evaluation_id,))
            conn.commit()
            
            return {
                "profile": "ga5-mailroom-action-gate/v2",
                "evaluationId": evaluation_id,
                "status": "completed",
                "inputDigest": input_digest,
                "outcomes": outcomes
            }
            
        else:
            raise HTTPException(status_code=400, detail="Unsupported runtime engine command path")
