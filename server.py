from dotenv import load_dotenv
from pathlib import Path
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

import os
import logging
import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional
import bcrypt
import jwt
import secrets
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request, BackgroundTasks
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr

from notifications import (
    send_email, send_push,
    build_password_reset_email, build_rsvp_notification_email,
    APP_PUBLIC_URL,
)


# ---------- Setup ----------
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

JWT_SECRET = os.environ.get("JWT_SECRET", "dev-secret-change-me")
JWT_ALG = "HS256"
ACCESS_TOKEN_DAYS = 30  # mobile apps: long-lived token

app = FastAPI()
api = APIRouter(prefix="/api")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("nuntamea")


# ---------- Helpers ----------
def hash_password(p: str) -> str:
    return bcrypt.hashpw(p.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(p: str, h: str) -> bool:
    try:
        return bcrypt.checkpw(p.encode("utf-8"), h.encode("utf-8"))
    except Exception:
        return False


def create_token(uid: str, email: str) -> str:
    payload = {
        "sub": uid,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(days=ACCESS_TOKEN_DAYS),
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)


async def get_current_user(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    token = auth[7:] if auth.startswith("Bearer ") else None
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = await db.users.find_one({"uid": payload["sub"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Models ----------
class RegisterIn(BaseModel):
    email: EmailStr
    password: str = Field(min_length=6)
    display_name: str = Field(min_length=1, max_length=80)


class LoginIn(BaseModel):
    email: EmailStr
    password: str


class UpdateProfileIn(BaseModel):
    display_name: Optional[str] = None
    buget_total: Optional[int] = None
    data_nunta: Optional[str] = None  # ISO date


class TaskCheckIn(BaseModel):
    task_id: str
    bifat: bool


class CheltuialaIn(BaseModel):
    titlu: str
    suma: float
    categoria: str


class FurnizorIn(BaseModel):
    tip: str
    nume: str
    telefon: Optional[str] = ""
    status: Optional[str] = "in_discutie"  # in_discutie / rezervat / platit
    pret: Optional[float] = 0
    avans: Optional[float] = 0


class InvitatIn(BaseModel):
    nume: str
    confirmat: Optional[str] = "in_asteptare"  # confirmat / refuzat / in_asteptare
    meniu: Optional[str] = "standard"
    masa: Optional[str] = ""
    telefon: Optional[str] = ""
    observatii: Optional[str] = ""


class LocationIn(BaseModel):
    ora: Optional[str] = ""
    eveniment: Optional[str] = ""
    locatie: Optional[str] = ""
    adresa: Optional[str] = ""
    harta_url: Optional[str] = ""


class InvitationSetupIn(BaseModel):
    mireasa: Optional[str] = ""
    mire: Optional[str] = ""
    couple_photo: Optional[str] = ""  # base64 data url
    nas: Optional[str] = ""
    nasa: Optional[str] = ""
    tata_mire: Optional[str] = ""
    mama_mire: Optional[str] = ""
    tata_mireasa: Optional[str] = ""
    mama_mireasa: Optional[str] = ""
    locations: Optional[List[LocationIn]] = []
    theme: Optional[str] = "ivory_elegant"  # ivory_elegant | blush_romance | sage_garden


class RsvpIn(BaseModel):
    confirmat: str  # confirmat | refuzat


class TimelineIn(BaseModel):
    titlu: str
    ora: str  # HH:MM


class ForgotPasswordIn(BaseModel):
    email: EmailStr


class ResetPasswordIn(BaseModel):
    token: str
    new_password: str = Field(min_length=6)


class PushTokenIn(BaseModel):
    token: str
    platform: Optional[str] = "android"


# ---------- Auth ----------
@api.post("/auth/register")
async def register(body: RegisterIn):
    email = body.email.lower().strip()
    if await db.users.find_one({"email": email}):
        raise HTTPException(status_code=400, detail="Email-ul este deja folosit")
    uid = str(uuid.uuid4())
    doc = {
        "uid": uid,
        "email": email,
        "display_name": body.display_name,
        "password_hash": hash_password(body.password),
        "buget_total": 0,
        "data_nunta": None,
        "created_at": now_iso(),
    }
    await db.users.insert_one(doc)
    token = create_token(uid, email)
    user = {k: v for k, v in doc.items() if k not in ("_id", "password_hash")}
    return {"user": user, "access_token": token}


@api.post("/auth/login")
async def login(body: LoginIn):
    email = body.email.lower().strip()
    u = await db.users.find_one({"email": email})
    if not u or not verify_password(body.password, u["password_hash"]):
        raise HTTPException(status_code=401, detail="Email sau parolă incorectă")
    token = create_token(u["uid"], u["email"])
    u.pop("_id", None)
    u.pop("password_hash", None)
    return {"user": u, "access_token": token}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    return {"user": user}


@api.post("/auth/logout")
async def logout(user=Depends(get_current_user)):
    return {"ok": True}


# ---------- Forgot Password ----------
@api.post("/auth/forgot-password")
async def forgot_password(body: ForgotPasswordIn, background: BackgroundTasks):
    """Send password reset email. Always returns OK to avoid email enumeration."""
    email = body.email.lower().strip()
    user = await db.users.find_one({"email": email})
    if user:
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        await db.password_reset_tokens.update_one(
            {"uid": user["uid"]},
            {"$set": {"uid": user["uid"], "token": token, "email": email, "expires_at": expires, "used": False}},
            upsert=True,
        )
        reset_link = f"{APP_PUBLIC_URL}/reset-password?token={token}"
        subject, html = build_password_reset_email(user.get("display_name", ""), reset_link)
        background.add_task(send_email, email, subject, html)
        logger.info("Password reset email queued for %s", email)
    # Always return OK
    return {"ok": True, "message": "Dacă există un cont cu acest email, vei primi un link de resetare."}


@api.post("/auth/reset-password")
async def reset_password(body: ResetPasswordIn):
    """Reset password using token from email link."""
    rec = await db.password_reset_tokens.find_one({"token": body.token, "used": False})
    if not rec:
        raise HTTPException(status_code=400, detail="Link invalid sau deja folosit")
    try:
        expires = datetime.fromisoformat(rec["expires_at"])
        if expires < datetime.now(timezone.utc):
            raise HTTPException(status_code=400, detail="Link expirat. Cere unul nou.")
    except (ValueError, TypeError):
        raise HTTPException(status_code=400, detail="Link invalid")
    await db.users.update_one(
        {"uid": rec["uid"]},
        {"$set": {"password_hash": hash_password(body.new_password)}},
    )
    await db.password_reset_tokens.update_one({"token": body.token}, {"$set": {"used": True}})
    return {"ok": True, "message": "Parola a fost resetată cu succes"}


# ---------- Push Tokens ----------
@api.post("/auth/push-token")
async def register_push_token(body: PushTokenIn, user=Depends(get_current_user)):
    """Register Expo push token for the authenticated user."""
    if not body.token or not body.token.startswith("ExponentPushToken["):
        return {"ok": False, "reason": "invalid_token_format"}
    await db.push_tokens.update_one(
        {"token": body.token},
        {"$set": {
            "uid": user["uid"],
            "token": body.token,
            "platform": body.platform or "android",
            "updated_at": now_iso(),
        }},
        upsert=True,
    )
    return {"ok": True}


@api.delete("/auth/push-token")
async def unregister_push_token(body: PushTokenIn, user=Depends(get_current_user)):
    """Remove a push token (e.g. on logout)."""
    await db.push_tokens.delete_one({"token": body.token, "uid": user["uid"]})
    return {"ok": True}


@api.delete("/auth/delete-account")
async def delete_account(user=Depends(get_current_user)):
    """GDPR: full account + data deletion (right to erasure)."""
    uid = user["uid"]
    # Delete all user data across collections
    results = {
        "cheltuieli": (await db.cheltuieli.delete_many({"user_id": uid})).deleted_count,
        "furnizori": (await db.furnizori.delete_many({"user_id": uid})).deleted_count,
        "invitati": (await db.invitati.delete_many({"user_id": uid})).deleted_count,
        "timeline": (await db.timeline.delete_many({"user_id": uid})).deleted_count,
        "user_checklist": (await db.user_checklist.delete_many({"user_id": uid})).deleted_count,
        # Custom checklist tasks owned by user
        "custom_tasks": (await db.checklist.delete_many({"owner_uid": uid})).deleted_count,
        "user": (await db.users.delete_one({"uid": uid})).deleted_count,
    }
    logger.info("Account deleted: uid=%s, summary=%s", uid, results)
    return {"deleted": True, "summary": results}


@api.put("/auth/profile")
async def update_profile(body: UpdateProfileIn, user=Depends(get_current_user)):
    upd = {k: v for k, v in body.model_dump().items() if v is not None}
    if upd:
        await db.users.update_one({"uid": user["uid"]}, {"$set": upd})
    fresh = await db.users.find_one({"uid": user["uid"]}, {"_id": 0, "password_hash": 0})
    return {"user": fresh}


# ---------- Checklist (global tasks + per-user state) ----------
@api.get("/checklist")
async def get_checklist(user=Depends(get_current_user)):
    # Show all global tasks (no owner_uid) + only this user's own custom tasks
    tasks = await db.checklist.find(
        {"$or": [{"owner_uid": {"$exists": False}}, {"owner_uid": user["uid"]}]},
        {"_id": 0},
    ).to_list(2000)
    checks = await db.user_checklist.find(
        {"user_id": user["uid"], "bifat": True}, {"_id": 0}
    ).to_list(2000)
    checked_ids = {c["task_id"] for c in checks}
    for t in tasks:
        t["bifat"] = t["task_id"] in checked_ids
    tasks.sort(key=lambda t: (t.get("ordine", 9999), t.get("categorie", ""), t.get("titlu", "")))
    return {"tasks": tasks}


class TaskAddIn(BaseModel):
    titlu: str = Field(min_length=1, max_length=200)
    categorie: str = Field(min_length=1, max_length=80)


@api.post("/checklist/add")
async def add_custom_task(body: TaskAddIn, user=Depends(get_current_user)):
    """Allow users to add their own personal tasks. Stored as global but tagged with owner_uid so only they see/can delete."""
    doc = {
        "task_id": str(uuid.uuid4()),
        "titlu": body.titlu.strip(),
        "categorie": body.categorie.strip(),
        "owner_uid": user["uid"],
        "ordine": 9999,
        "created_at": now_iso(),
    }
    await db.checklist.insert_one(doc.copy())
    doc.pop("_id", None)
    doc["bifat"] = False
    return {"task": doc}


@api.delete("/checklist/{task_id}")
async def delete_custom_task(task_id: str, user=Depends(get_current_user)):
    """Delete a user's own custom task. Cannot delete global tasks."""
    task = await db.checklist.find_one({"task_id": task_id})
    if not task:
        raise HTTPException(status_code=404, detail="Task inexistent")
    if task.get("owner_uid") != user["uid"]:
        raise HTTPException(status_code=403, detail="Nu poți șterge task-uri implicite")
    await db.checklist.delete_one({"task_id": task_id})
    await db.user_checklist.delete_many({"task_id": task_id})
    return {"deleted": 1}


@api.post("/checklist/check")
async def check_task(body: TaskCheckIn, user=Depends(get_current_user)):
    task = await db.checklist.find_one({"task_id": body.task_id})
    if not task:
        raise HTTPException(status_code=404, detail="Task inexistent")
    doc_id = f"{user['uid']}_{body.task_id}"
    await db.user_checklist.update_one(
        {"_id": doc_id},
        {"$set": {
            "_id": doc_id,
            "user_id": user["uid"],
            "task_id": body.task_id,
            "bifat": body.bifat,
            "updated_at": now_iso(),
        }},
        upsert=True,
    )
    return {"ok": True, "bifat": body.bifat}


# ---------- Cheltuieli (Buget) ----------
@api.get("/cheltuieli")
async def list_cheltuieli(user=Depends(get_current_user)):
    items = await db.cheltuieli.find(
        {"user_id": user["uid"]}, {"_id": 0}
    ).sort("data", -1).to_list(2000)
    total = sum(float(i.get("suma", 0)) for i in items)
    return {"items": items, "total_cheltuit": total}


@api.post("/cheltuieli")
async def add_cheltuiala(body: CheltuialaIn, user=Depends(get_current_user)):
    doc = {
        "id": str(uuid.uuid4()),
        "titlu": body.titlu,
        "suma": float(body.suma),
        "categoria": body.categoria,
        "user_id": user["uid"],
        "data": now_iso(),
    }
    await db.cheltuieli.insert_one(doc.copy())
    doc.pop("_id", None)
    return {"item": doc}


@api.delete("/cheltuieli/{item_id}")
async def del_cheltuiala(item_id: str, user=Depends(get_current_user)):
    res = await db.cheltuieli.delete_one({"id": item_id, "user_id": user["uid"]})
    return {"deleted": res.deleted_count}


# ---------- Furnizori ----------
async def _sync_furnizor_to_buget(furnizor: dict):
    """Auto-create/update a linked cheltuiala when furnizor has avans > 0.
    Idempotent: id = 'furn_<furnizor_id>'."""
    cheltuiala_id = f"furn_{furnizor['id']}"
    avans = float(furnizor.get("avans") or 0)
    if avans > 0:
        await db.cheltuieli.update_one(
            {"id": cheltuiala_id},
            {"$set": {
                "id": cheltuiala_id,
                "user_id": furnizor["user_id"],
                "titlu": f"Avans {furnizor.get('tip','')}: {furnizor.get('nume','')}".strip(),
                "suma": avans,
                "categoria": furnizor.get("tip", "Altele"),
                "data": now_iso(),
                "linked_furnizor": furnizor["id"],
            }},
            upsert=True,
        )
    else:
        await db.cheltuieli.delete_one({"id": cheltuiala_id})


@api.get("/furnizori")
async def list_furnizori(user=Depends(get_current_user)):
    items = await db.furnizori.find(
        {"user_id": user["uid"]}, {"_id": 0}
    ).sort("created_at", -1).to_list(2000)
    return {"items": items}


@api.post("/furnizori")
async def add_furnizor(body: FurnizorIn, user=Depends(get_current_user)):
    avans = float(body.avans or 0)
    pret = float(body.pret or 0)
    status = body.status or "in_discutie"
    # Auto-status logic: avans>=pret(and pret>0) -> platit; avans>0 -> rezervat (only if not manually advanced)
    order = {"in_discutie": 0, "rezervat": 1, "platit": 2}
    auto = "in_discutie"
    if pret > 0 and avans >= pret:
        auto = "platit"
    elif avans > 0:
        auto = "rezervat"
    if order.get(auto, 0) > order.get(status, 0):
        status = auto
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["uid"],
        "tip": body.tip,
        "nume": body.nume,
        "telefon": body.telefon or "",
        "status": status,
        "pret": pret,
        "avans": avans,
        "created_at": now_iso(),
    }
    await db.furnizori.insert_one(doc.copy())
    doc.pop("_id", None)
    await _sync_furnizor_to_buget(doc)
    return {"item": doc}


@api.put("/furnizori/{item_id}")
async def upd_furnizor(item_id: str, body: FurnizorIn, user=Depends(get_current_user)):
    upd = body.model_dump()
    upd["pret"] = float(upd.get("pret") or 0)
    upd["avans"] = float(upd.get("avans") or 0)
    cur_status = upd.get("status") or "in_discutie"
    order = {"in_discutie": 0, "rezervat": 1, "platit": 2}
    auto = "in_discutie"
    if upd["pret"] > 0 and upd["avans"] >= upd["pret"]:
        auto = "platit"
    elif upd["avans"] > 0:
        auto = "rezervat"
    # Bump up the status only (never downgrade what user manually chose)
    if order.get(auto, 0) > order.get(cur_status, 0):
        upd["status"] = auto
    await db.furnizori.update_one({"id": item_id, "user_id": user["uid"]}, {"$set": upd})
    fresh = await db.furnizori.find_one({"id": item_id, "user_id": user["uid"]}, {"_id": 0})
    if fresh:
        await _sync_furnizor_to_buget(fresh)
    return {"item": fresh}


@api.delete("/furnizori/{item_id}")
async def del_furnizor(item_id: str, user=Depends(get_current_user)):
    res = await db.furnizori.delete_one({"id": item_id, "user_id": user["uid"]})
    # Also remove the linked cheltuiala
    await db.cheltuieli.delete_one({"id": f"furn_{item_id}", "user_id": user["uid"]})
    return {"deleted": res.deleted_count}


# ---------- Invitati ----------
@api.get("/invitati")
async def list_invitati(user=Depends(get_current_user)):
    items = await db.invitati.find(
        {"user_id": user["uid"]}, {"_id": 0}
    ).sort("nume", 1).to_list(5000)
    stats = {
        "total": len(items),
        "confirmati": sum(1 for i in items if i.get("confirmat") == "confirmat"),
        "refuzati": sum(1 for i in items if i.get("confirmat") == "refuzat"),
        "in_asteptare": sum(1 for i in items if i.get("confirmat") == "in_asteptare"),
    }
    return {"items": items, "stats": stats}


@api.post("/invitati")
async def add_invitat(body: InvitatIn, user=Depends(get_current_user)):
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["uid"],
        "nume": body.nume,
        "confirmat": body.confirmat or "in_asteptare",
        "meniu": body.meniu or "standard",
        "masa": body.masa or "",
        "telefon": body.telefon or "",
        "observatii": body.observatii or "",
        "created_at": now_iso(),
    }
    await db.invitati.insert_one(doc.copy())
    doc.pop("_id", None)
    return {"item": doc}


@api.put("/invitati/{item_id}")
async def upd_invitat(item_id: str, body: InvitatIn, user=Depends(get_current_user)):
    upd = body.model_dump()
    await db.invitati.update_one({"id": item_id, "user_id": user["uid"]}, {"$set": upd})
    fresh = await db.invitati.find_one({"id": item_id, "user_id": user["uid"]}, {"_id": 0})
    return {"item": fresh}


@api.delete("/invitati/{item_id}")
async def del_invitat(item_id: str, user=Depends(get_current_user)):
    res = await db.invitati.delete_one({"id": item_id, "user_id": user["uid"]})
    return {"deleted": res.deleted_count}


# ---------- Timeline (Ziua Z) ----------
@api.get("/timeline")
async def list_timeline(user=Depends(get_current_user)):
    items = await db.timeline.find(
        {"user_id": user["uid"]}, {"_id": 0}
    ).sort("ora", 1).to_list(500)
    return {"items": items}


@api.post("/timeline")
async def add_timeline(body: TimelineIn, user=Depends(get_current_user)):
    doc = {
        "id": str(uuid.uuid4()),
        "user_id": user["uid"],
        "titlu": body.titlu,
        "ora": body.ora,
        "created_at": now_iso(),
    }
    await db.timeline.insert_one(doc.copy())
    doc.pop("_id", None)
    return {"item": doc}


@api.delete("/timeline/{item_id}")
async def del_timeline(item_id: str, user=Depends(get_current_user)):
    res = await db.timeline.delete_one({"id": item_id, "user_id": user["uid"]})
    return {"deleted": res.deleted_count}


@api.put("/timeline/{item_id}")
async def edit_timeline(item_id: str, body: TimelineIn, user=Depends(get_current_user)):
    res = await db.timeline.update_one(
        {"id": item_id, "user_id": user["uid"]},
        {"$set": {"titlu": body.titlu, "ora": body.ora}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Moment inexistent")
    return {"ok": True}


# ---------- Health ----------
@api.get("/")
async def root():
    return {"message": "NuntaMea API"}


# ---------- Invitation Setup (auth) ----------
@api.get("/invitation/setup")
async def get_invitation_setup(user=Depends(get_current_user)):
    fresh = await db.users.find_one({"uid": user["uid"]}, {"_id": 0, "password_hash": 0})
    setup = (fresh or {}).get("invitation_setup") or {}
    # Default mireasa/mire from display_name if not set
    if not setup.get("mireasa") and not setup.get("mire") and fresh:
        dn = fresh.get("display_name", "")
        if "&" in dn:
            parts = [p.strip() for p in dn.split("&", 1)]
            setup["mireasa"] = setup.get("mireasa") or parts[0]
            setup["mire"] = setup.get("mire") or (parts[1] if len(parts) > 1 else "")
    return {"setup": setup, "data_nunta": (fresh or {}).get("data_nunta")}


@api.put("/invitation/setup")
async def put_invitation_setup(body: InvitationSetupIn, user=Depends(get_current_user)):
    setup = body.model_dump()
    await db.users.update_one({"uid": user["uid"]}, {"$set": {"invitation_setup": setup}})
    return {"ok": True, "setup": setup}


# ---------- Public invitation routes (NO auth) ----------
@api.get("/invitation/{code}")
async def public_invitation(code: str):
    invitat = await db.invitati.find_one({"id": code}, {"_id": 0})
    if not invitat:
        raise HTTPException(status_code=404, detail="Invitație inexistentă")
    user = await db.users.find_one({"uid": invitat["user_id"]}, {"_id": 0, "password_hash": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Cuplul nu mai există")
    return {
        "guest": {
            "nume": invitat.get("nume", ""),
            "confirmat": invitat.get("confirmat", "in_asteptare"),
            "code": code,
        },
        "couple": {
            "display_name": user.get("display_name", ""),
            "data_nunta": user.get("data_nunta"),
        },
        "setup": user.get("invitation_setup") or {},
    }


@api.post("/invitation/{code}/rsvp")
async def public_rsvp(code: str, body: RsvpIn, background: BackgroundTasks):
    if body.confirmat not in ("confirmat", "refuzat"):
        raise HTTPException(status_code=400, detail="Status invalid")
    invitat = await db.invitati.find_one({"id": code}, {"_id": 0})
    if not invitat:
        raise HTTPException(status_code=404, detail="Invitație inexistentă")
    await db.invitati.update_one(
        {"id": code},
        {"$set": {"confirmat": body.confirmat, "responded_at": now_iso()}},
    )
    # Notify the couple (email + push) — non-blocking, never fails the request
    user = await db.users.find_one({"uid": invitat["user_id"]}, {"_id": 0, "password_hash": 0})
    if user:
        guest_name = invitat.get("nume", "Un invitat")
        couple_display = user.get("display_name", "")
        # Email
        if user.get("email"):
            subject, html = build_rsvp_notification_email(couple_display, guest_name, body.confirmat)
            background.add_task(send_email, user["email"], subject, html)
        # Push
        tokens_cursor = db.push_tokens.find({"uid": user["uid"]}, {"_id": 0, "token": 1})
        tokens = [t["token"] async for t in tokens_cursor]
        if tokens:
            label = "a confirmat ✓" if body.confirmat == "confirmat" else "a refuzat ✗"
            background.add_task(
                send_push,
                tokens,
                f"{guest_name} {label}",
                "Vezi toate răspunsurile în aplicație",
                {"type": "rsvp", "code": code, "status": body.confirmat},
            )
    return {"ok": True, "confirmat": body.confirmat}


# ---------- Public HTML invitation page (served at /invite/{code}, no /api prefix) ----------
@app.get("/reset-password", response_class=None)
async def reset_password_page(token: str = ""):
    """Public HTML page for password reset (linked from email)."""
    from fastapi.responses import HTMLResponse
    if not token:
        return HTMLResponse(_render_reset_invalid("Link invalid sau lipsește token-ul."), status_code=400)
    rec = await db.password_reset_tokens.find_one({"token": token, "used": False})
    if not rec:
        return HTMLResponse(_render_reset_invalid("Link invalid sau deja folosit."), status_code=400)
    try:
        if datetime.fromisoformat(rec["expires_at"]) < datetime.now(timezone.utc):
            return HTMLResponse(_render_reset_invalid("Link expirat. Cere unul nou din aplicație."), status_code=400)
    except Exception:
        return HTMLResponse(_render_reset_invalid("Link invalid."), status_code=400)
    return HTMLResponse(_render_reset_form(token, rec.get("email", "")))


def _render_reset_invalid(msg: str) -> str:
    return f"""<!DOCTYPE html><html lang="ro"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Resetare parolă</title>
<style>body{{font-family:-apple-system,sans-serif;text-align:center;padding:60px 20px;background:#FFF8F5;color:#2A1F2D}}h1{{color:#E8789A;font-family:Georgia,serif}}.box{{max-width:440px;margin:0 auto;background:#fff;border-radius:18px;padding:32px}}.btn{{display:inline-block;margin-top:20px;background:#E8789A;color:#fff;padding:12px 28px;border-radius:10px;text-decoration:none;font-weight:600}}</style>
</head><body><div class="box"><h1>💔 Oops</h1><p>{msg}</p></div></body></html>"""


def _render_reset_form(token: str, email: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="ro"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Resetare parolă — Nunta Mea</title>
<style>
*{{box-sizing:border-box;margin:0;padding:0}}
body{{font-family:'Inter',-apple-system,sans-serif;background:linear-gradient(180deg,#FFF8F5 0%,#FDE6EC 100%);min-height:100vh;padding:32px 16px;color:#2A1F2D}}
.card{{max-width:440px;margin:0 auto;background:#fff;border-radius:24px;padding:36px 28px;box-shadow:0 12px 40px rgba(232,120,154,0.15)}}
h1{{font-family:'Playfair Display',Georgia,serif;font-size:28px;color:#E8789A;text-align:center;margin-bottom:8px}}
.sub{{text-align:center;color:#8B7A86;font-size:14px;margin-bottom:24px}}
.email{{background:#FFF8F5;border-radius:8px;padding:10px 14px;font-size:13px;color:#8B7A86;text-align:center;margin-bottom:20px}}
label{{display:block;font-size:13px;color:#8B7A86;font-weight:500;margin-bottom:6px;margin-top:14px}}
input{{width:100%;padding:14px;border:1px solid #F1E4E0;border-radius:10px;font-size:15px;color:#2A1F2D;font-family:inherit;background:#fff}}
input:focus{{outline:none;border-color:#E8789A}}
.btn{{width:100%;background:#E8789A;color:#fff;border:none;padding:16px;border-radius:10px;font-size:16px;font-weight:600;cursor:pointer;margin-top:22px;-webkit-tap-highlight-color:transparent}}
.btn:disabled{{opacity:0.6}}
.error{{background:#FFE8E8;color:#E27676;padding:12px;border-radius:8px;font-size:13px;margin-top:12px;text-align:center;display:none}}
.success{{background:#E8F8EE;color:#5BA678;padding:14px;border-radius:8px;font-size:14px;margin-top:12px;text-align:center;display:none}}
.heart{{text-align:center;font-size:42px;margin-bottom:8px}}
</style></head><body>
<div class="card">
  <div class="heart">💍</div>
  <h1>Setează parolă nouă</h1>
  <p class="sub">pentru contul tău Nunta Mea</p>
  <div class="email">{email}</div>
  <form id="f">
    <label>Parolă nouă (minim 6 caractere)</label>
    <input type="password" id="p1" minlength="6" required autocomplete="new-password" />
    <label>Confirmă parola</label>
    <input type="password" id="p2" minlength="6" required autocomplete="new-password" />
    <div class="error" id="err"></div>
    <div class="success" id="ok"></div>
    <button type="submit" class="btn" id="btn">Salvează parola nouă</button>
  </form>
</div>
<script>
const f=document.getElementById('f'),p1=document.getElementById('p1'),p2=document.getElementById('p2'),err=document.getElementById('err'),ok=document.getElementById('ok'),btn=document.getElementById('btn');
f.addEventListener('submit',async e=>{{
  e.preventDefault();err.style.display='none';ok.style.display='none';
  if(p1.value!==p2.value){{err.textContent='Parolele nu se potrivesc';err.style.display='block';return}}
  if(p1.value.length<6){{err.textContent='Parola trebuie să aibă cel puțin 6 caractere';err.style.display='block';return}}
  btn.disabled=true;btn.textContent='Se salvează...';
  try{{
    const r=await fetch('/api/auth/reset-password',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify({{token:'{token}',new_password:p1.value}})}});
    const data=await r.json();
    if(!r.ok)throw new Error(data.detail||'Eroare');
    ok.textContent='✓ Parolă resetată! Acum poți intra în aplicație cu noua parolă.';ok.style.display='block';
    f.querySelectorAll('input,button').forEach(x=>x.disabled=true);
  }}catch(ex){{err.textContent=ex.message||'Eroare necunoscută';err.style.display='block';btn.disabled=false;btn.textContent='Salvează parola nouă';}}
}});
</script>
</body></html>"""


# ---------- Public HTML invitation page (served at /invite/{code}, no /api prefix) ----------
@app.get("/invite/{code}", response_class=None)
async def public_invitation_html(code: str):
    from fastapi.responses import HTMLResponse
    invitat = await db.invitati.find_one({"id": code}, {"_id": 0})
    if not invitat:
        return HTMLResponse(_render_not_found(), status_code=404)
    user = await db.users.find_one({"uid": invitat["user_id"]}, {"_id": 0, "password_hash": 0})
    if not user:
        return HTMLResponse(_render_not_found(), status_code=404)
    setup = user.get("invitation_setup") or {}
    return HTMLResponse(_render_invitation(code, invitat, user, setup))


# ---------- Asset download helpers (Play Store icon, etc.) ----------
@api.get("/assets/play-store-icon")
async def download_play_store_icon():
    from fastapi.responses import FileResponse
    import os as _os
    candidates = [
        "/app/play-store-icon-512.png",
        "/app/frontend/assets/images/play-store-icon-512.png",
    ]
    for p in candidates:
        if _os.path.exists(p):
            return FileResponse(
                p,
                media_type="image/png",
                filename="nuntamea-play-store-icon-512.png",
            )
    raise HTTPException(status_code=404, detail="Asset not found")


def _render_not_found() -> str:
    return """<!DOCTYPE html>
<html lang="ro"><head><meta charset="UTF-8"><title>Invitație inexistentă</title>
<style>body{font-family:-apple-system,sans-serif;text-align:center;padding:80px 20px;background:#FFF8F5;color:#2d2d2d}h1{color:#E8789A}</style>
</head><body><h1>Invitație inexistentă 💔</h1><p>Link-ul pe care l-ai accesat nu mai este valid.</p></body></html>"""


def _render_invitation(code: str, invitat: dict, user: dict, setup: dict) -> str:
    guest_nume = invitat.get("nume", "")
    already_confirmed = invitat.get("confirmat") == "confirmat"
    already_declined = invitat.get("confirmat") == "refuzat"
    mireasa = setup.get("mireasa") or (user.get("display_name") or "").split("&")[0].strip() or "Mireasa"
    mire = setup.get("mire") or ""
    if not mire and "&" in (user.get("display_name") or ""):
        mire = (user.get("display_name") or "").split("&", 1)[1].strip()
    mire = mire or "Mirele"
    data_nunta = user.get("data_nunta") or ""
    data_fmt = ""
    if data_nunta:
        try:
            dt = datetime.fromisoformat(data_nunta.replace("Z", "+00:00"))
            luni = ["ianuarie", "februarie", "martie", "aprilie", "mai", "iunie", "iulie", "august", "septembrie", "octombrie", "noiembrie", "decembrie"]
            data_fmt = f"{dt.day} {luni[dt.month - 1]} {dt.year}"
        except Exception:
            data_fmt = data_nunta
    photo = setup.get("couple_photo") or ""
    locations = setup.get("locations") or []
    godparents = setup.get("godparents") or {}
    godp_txt = ""
    if godparents.get("nume_nasa") or godparents.get("nume_nas"):
        n1 = godparents.get("nume_nasa") or ""
        n2 = godparents.get("nume_nas") or ""
        godp_txt = f"<p class='godparents'>Nași: {n1}{' & ' if n1 and n2 else ''}{n2}</p>"

    locations_html = ""
    for loc in locations:
        if loc.get("eveniment") or loc.get("locatie"):
            ora = loc.get("ora", "")
            ev = loc.get("eveniment", "")
            locatie = loc.get("locatie", "")
            adresa = loc.get("adresa", "")
            locations_html += f"""
            <div class="loc">
              <div class="loc-time">{ora}</div>
              <div class="loc-event">{ev}</div>
              <div class="loc-place">{locatie}</div>
              {f'<div class="loc-addr">{adresa}</div>' if adresa else ''}
            </div>"""

    photo_block = f'<img src="{photo}" alt="" class="couple-photo" />' if photo else '<div class="heart">💕</div>'

    rsvp_block = ""
    if already_confirmed:
        rsvp_block = '<div class="rsvp-done confirmed">Ne bucurăm! Te așteptăm! 🎊</div>'
    elif already_declined:
        rsvp_block = '<div class="rsvp-done declined">Îți mulțumim că ne-ai anunțat! 💕</div>'
    else:
        rsvp_block = f'''
        <p class="rsvp-q">Dragă <strong>{guest_nume}</strong>,<br/>ne onorezi cu prezența?</p>
        <button class="btn-yes" onclick="rsvp('confirmat')">✓ Vin cu drag!</button>
        <button class="btn-no" onclick="rsvp('refuzat')">✗ Nu pot veni</button>
        <div id="submitting" style="display:none;margin-top:12px;color:#888">Se trimite...</div>
        '''

    return f"""<!DOCTYPE html>
<html lang="ro">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>Invitație nuntă — {mireasa} & {mire}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Playfair Display', Georgia, serif; background: linear-gradient(180deg, #FFF8F5 0%, #FDE6EC 100%); color: #2d2d2d; min-height: 100vh; padding: 24px 16px; }}
  .card {{ max-width: 480px; margin: 0 auto; background: #fff; border-radius: 24px; box-shadow: 0 12px 40px rgba(232, 120, 154, 0.18); overflow: hidden; }}
  .hero {{ position: relative; width: 100%; aspect-ratio: 3/4; background: #F5D5DC; display: flex; align-items: center; justify-content: center; overflow: hidden; }}
  .couple-photo {{ width: 100%; height: 100%; object-fit: cover; }}
  .heart {{ font-size: 120px; opacity: 0.35; }}
  .hero::after {{ content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, transparent 50%, rgba(0,0,0,0.6) 100%); }}
  .hero-text {{ position: absolute; bottom: 30px; left: 0; right: 0; text-align: center; color: #fff; z-index: 2; padding: 0 20px; }}
  .hero-names {{ font-size: 34px; font-weight: 400; line-height: 1.2; letter-spacing: 1px; text-shadow: 0 2px 12px rgba(0,0,0,0.3); }}
  .hero-names .amp {{ color: #FFD4DE; font-style: italic; padding: 0 6px; }}
  .hero-date {{ font-size: 13px; letter-spacing: 3px; margin-top: 10px; font-family: 'Inter', sans-serif; opacity: 0.95; }}
  .body {{ padding: 32px 28px 40px; text-align: center; font-family: 'Inter', sans-serif; }}
  .intro {{ font-size: 15px; color: #6b6b6b; line-height: 1.7; margin-bottom: 22px; }}
  .godparents {{ font-size: 14px; color: #8e7a80; font-style: italic; margin-bottom: 20px; }}
  .loc {{ border-top: 1px solid #f0e0e5; padding: 18px 0; }}
  .loc:last-of-type {{ border-bottom: 1px solid #f0e0e5; margin-bottom: 24px; }}
  .loc-time {{ font-family: 'Playfair Display', serif; font-size: 22px; color: #E8789A; font-style: italic; }}
  .loc-event {{ font-size: 15px; font-weight: 600; color: #2d2d2d; margin-top: 4px; }}
  .loc-place {{ font-size: 13px; color: #6b6b6b; margin-top: 2px; }}
  .loc-addr {{ font-size: 12px; color: #8e8e8e; margin-top: 2px; }}
  .rsvp-q {{ font-family: 'Playfair Display', serif; font-size: 20px; color: #2d2d2d; margin-top: 24px; margin-bottom: 18px; line-height: 1.5; }}
  .btn-yes, .btn-no {{ display: block; width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-bottom: 10px; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; transition: transform 0.1s; }}
  .btn-yes {{ background: #E8789A; color: #fff; }}
  .btn-yes:active {{ transform: scale(0.97); }}
  .btn-no {{ background: #fff; color: #8e8e8e; border: 1.5px solid #e5d8de; }}
  .btn-no:active {{ transform: scale(0.97); }}
  .rsvp-done {{ padding: 22px; border-radius: 12px; font-family: 'Playfair Display', serif; font-size: 19px; }}
  .rsvp-done.confirmed {{ background: #FDE6EC; color: #2d2d2d; }}
  .rsvp-done.declined {{ background: #F5E5E5; color: #2d2d2d; }}
  .footer {{ text-align: center; margin-top: 24px; font-size: 11px; color: #b8a5ac; font-family: 'Inter', sans-serif; letter-spacing: 2px; }}
</style>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
</head>
<body>
  <div class="card">
    <div class="hero">
      {photo_block}
      <div class="hero-text">
        <div class="hero-names">{mireasa} <span class="amp">&</span> {mire}</div>
        {f'<div class="hero-date">{data_fmt.upper()}</div>' if data_fmt else ''}
      </div>
    </div>
    <div class="body">
      <p class="intro">Ne-ar face mare bucurie să ne fii alături<br/>în cea mai importantă zi a vieții noastre.</p>
      {godp_txt}
      {locations_html}
      {rsvp_block}
    </div>
  </div>
  <div class="footer">NUNTA MEA</div>
<script>
async function rsvp(status) {{
  const btns = document.querySelectorAll('.btn-yes, .btn-no');
  btns.forEach(b => b.disabled = true);
  document.getElementById('submitting').style.display = 'block';
  try {{
    const r = await fetch('/api/invitation/{code}/rsvp', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ confirmat: status }})
    }});
    if (!r.ok) throw new Error('Eroare');
    location.reload();
  }} catch (e) {{
    alert('A apărut o eroare. Te rugăm să încerci din nou.');
    btns.forEach(b => b.disabled = false);
    document.getElementById('submitting').style.display = 'none';
  }}
}}
</script>
</body></html>"""


# ---------- Seed ----------
DEFAULT_TASKS = [
    # Planificare inițială
    ("Stabilește data nunții", "Planificare inițială"),
    ("Stabilește bugetul total", "Planificare inițială"),
    ("Alege nașii", "Planificare inițială"),
    # Locație & Religie
    ("Alege locația pentru ceremonie", "Locație & Religie"),
    ("Alege sala de recepție", "Locație & Religie"),
    ("Rezervă biserica", "Locație & Religie"),
    ("Discută cu preotul detaliile ceremoniei", "Locație & Religie"),
    # Furnizori
    ("Angajează fotograful", "Furnizori"),
    ("Angajează videograful", "Furnizori"),
    ("Angajează formația/DJ", "Furnizori"),
    ("Angajează florarul", "Furnizori"),
    # Vestimentație
    ("Alege rochia de mireasă", "Vestimentație"),
    ("Alege costumul mirelui", "Vestimentație"),
    ("Alege verighetele", "Vestimentație"),
    # Călătorie
    ("Planifică luna de miere", "Călătorie"),
    # Invitați
    ("Creează lista de invitați", "Invitați"),
    ("Comandă invitațiile", "Invitați"),
    ("Trimite invitațiile", "Invitați"),
    ("Confirmă numărul de invitați", "Invitați"),
    ("Planifică aranjamentul la mese", "Invitați"),
    # Catering
    ("Alege meniul", "Catering"),
    ("Alege tortul de nuntă", "Catering"),
    # Pregătiri
    ("Rezervă cazarea pentru noaptea nunții", "Pregătiri"),
    ("Rezervă mașina de nuntă", "Pregătiri"),
    ("Rezervă salonul de coafură și machiaj", "Pregătiri"),
    ("Organizează petrecerea burlacilor", "Pregătiri"),
    ("Cumpără lumânările și cununiile pentru biserică", "Pregătiri"),
    # Acte & Confirmări
    ("Depune actele la starea civilă", "Acte & Confirmări"),
    ("Confirmă data și ora cu preotul", "Acte & Confirmări"),
    ("Confirmă prezența cu toți furnizorii", "Acte & Confirmări"),
    ("Pregătește plicurile pentru furnizori", "Acte & Confirmări"),
    ("Fă programul zilei nunții", "Acte & Confirmări"),
    # Ziua nunții
    ("Coafură și machiaj mireasă", "Ziua nunții"),
    ("Fotografii înainte de ceremonie", "Ziua nunții"),
    ("Ceremonia religioasă", "Ziua nunții"),
    ("Fotografii de grup", "Ziua nunții"),
    ("Sosire la restaurant", "Ziua nunții"),
    ("Primirea invitaților", "Ziua nunții"),
]


async def seed_checklist():
    # Re-seed: delete old global tasks not in current list, insert any missing.
    titles = {t[0] for t in DEFAULT_TASKS}
    await db.checklist.delete_many({"titlu": {"$nin": list(titles)}})
    for idx, (titlu, cat) in enumerate(DEFAULT_TASKS):
        existing = await db.checklist.find_one({"titlu": titlu})
        if not existing:
            await db.checklist.insert_one({
                "task_id": str(uuid.uuid4()),
                "titlu": titlu,
                "categorie": cat,
                "ordine": idx,
                "created_at": now_iso(),
            })
        else:
            await db.checklist.update_one(
                {"titlu": titlu},
                {"$set": {"categorie": cat, "ordine": idx}},
            )
    logger.info("Checklist seed complete: %d tasks", len(DEFAULT_TASKS))


async def cleanup_test_data():
    # Remove leftover test rows from automated testing agent
    for col in ("cheltuieli", "furnizori", "invitati", "timeline"):
        await db[col].delete_many({"$or": [
            {"titlu": {"$regex": "^TEST_"}},
            {"nume": {"$regex": "^TEST_"}},
        ]})


async def seed_test_user():
    email = "test@nuntamea.ro"
    if await db.users.find_one({"email": email}):
        return
    uid = str(uuid.uuid4())
    # Default wedding date in ~6 months for nice countdown
    wedding = (datetime.now(timezone.utc) + timedelta(days=180)).date().isoformat()
    await db.users.insert_one({
        "uid": uid,
        "email": email,
        "display_name": "Maria & Andrei",
        "password_hash": hash_password("test1234"),
        "buget_total": 80000,
        "data_nunta": wedding,
        "created_at": now_iso(),
    })
    logger.info("Test user seeded")


@app.on_event("startup")
async def on_startup():
    await db.users.create_index("email", unique=True)
    await db.checklist.create_index("task_id", unique=True)
    await db.user_checklist.create_index([("user_id", 1), ("task_id", 1)])
    await db.cheltuieli.create_index("user_id")
    await db.furnizori.create_index("user_id")
    await db.invitati.create_index("user_id")
    await db.timeline.create_index("user_id")
    await seed_checklist()
    # Dev helpers — only in non-production
    if os.environ.get("ENV", "production").lower() != "production":
        await cleanup_test_data()
        await seed_test_user()


@app.on_event("shutdown")
async def on_shutdown():
    client.close()


# Mount router & CORS
app.include_router(api)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=False,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
