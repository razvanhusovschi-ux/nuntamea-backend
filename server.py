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
from fastapi.responses import HTMLResponse, FileResponse
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
    language: Optional[str] = None  # ro / en / it / es


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
    prefix_tara: Optional[str] = ""  # international country prefix without + (e.g. "40", "39", "34", "44", "1")
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
    couple_photo: Optional[str] = ""  # base64 data url — used by the invitation card
    couple_photo_std: Optional[str] = ""  # separate photo used by Save the Date — independent from invitation
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


# ---------- Premium / Billing Models ----------
PREMIUM_FIELDS_DEFAULT = {
    "is_premium": False,
    "premium_purchased_at": None,
    "premium_source": None,  # "mock" | "play_store" | "app_store" | "revenuecat"
    "revenuecat_user_id": None,
}


def _ensure_premium_defaults(user: dict) -> dict:
    """Inject premium fields with defaults if missing on legacy users."""
    if not user:
        return user
    for k, v in PREMIUM_FIELDS_DEFAULT.items():
        user.setdefault(k, v)
    return user


class GrantMockPremiumIn(BaseModel):
    confirm: bool = True  # safety flag


class VerifyReceiptIn(BaseModel):
    """For future production verification via RevenueCat REST API."""
    revenuecat_user_id: Optional[str] = None
    play_store_token: Optional[str] = None
    product_id: Optional[str] = None


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
        **PREMIUM_FIELDS_DEFAULT,
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
    _ensure_premium_defaults(u)
    return {"user": u, "access_token": token}


@api.get("/auth/me")
async def me(user=Depends(get_current_user)):
    _ensure_premium_defaults(user)
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


@api.put("/cheltuieli/{item_id}")
async def upd_cheltuiala(item_id: str, body: CheltuialaIn, user=Depends(get_current_user)):
    """Edit a manual expense. Vendor-linked expenses (id starting with 'furn_') cannot be edited here."""
    if item_id.startswith("furn_"):
        raise HTTPException(status_code=400, detail="Cheltuielile legate de furnizori se editează din tab Furnizori")
    upd = {"titlu": body.titlu, "suma": float(body.suma), "categoria": body.categoria}
    res = await db.cheltuieli.update_one({"id": item_id, "user_id": user["uid"]}, {"$set": upd})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Cheltuială inexistentă")
    fresh = await db.cheltuieli.find_one({"id": item_id, "user_id": user["uid"]}, {"_id": 0})
    return {"item": fresh}


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
APP_VERSION = "1.2.5"

@api.get("/")
async def root():
    return {"message": "NuntaMea API", "version": APP_VERSION}


@api.get("/version")
async def version_check():
    """Returns the running server version + list of registered route methods. 
    Use this to verify Render has deployed the latest code."""
    routes_info = {}
    for r in app.routes:
        if hasattr(r, "path") and hasattr(r, "methods"):
            path = r.path
            if "/api/" in path:
                routes_info.setdefault(path, set()).update(r.methods or set())
    return {
        "version": APP_VERSION,
        "supports_edit_cheltuiala": "PUT" in routes_info.get("/api/cheltuieli/{item_id}", set()),
        "themes": ["ivory_elegant","blush_romance","sage_garden","gold_glamour","burgundy_passion","marble_modern","forest_woodland","dusty_rose"],
        "translations_check": {
            "inv_i18n_keys": list(INV_I18N.keys()) if "INV_I18N" in dir() else [],
        },
    }


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
@app.get("/reset-password", response_class=HTMLResponse, include_in_schema=False)
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
@app.get("/invite/{code}", response_class=HTMLResponse, include_in_schema=False)
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
@api.get("/assets/play-store-icon", include_in_schema=False)
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


@api.get("/assets/locale-ro", include_in_schema=False)
async def download_ro_locale():
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend/src/i18n/ro.json"
    if _os.path.exists(p):
        return FileResponse(p, media_type="application/json", filename="ro.json")
    raise HTTPException(status_code=404, detail="Locale file not found")


@api.get("/assets/locale-it-template", include_in_schema=False)
async def download_it_template():
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/it_template.json"
    if _os.path.exists(p):
        return FileResponse(p, media_type="application/json", filename="it.json")
    raise HTTPException(status_code=404, detail="Template not found")


@api.get("/assets/locale-es-template", include_in_schema=False)
async def download_es_template():
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/es_template.json"
    if _os.path.exists(p):
        return FileResponse(p, media_type="application/json", filename="es.json")
    raise HTTPException(status_code=404, detail="Template not found")


# ---------- Billing / Premium ----------
SANDBOX_BILLING = os.environ.get("BILLING_SANDBOX", "true").lower() == "true"

# Free tier limits (sent to client; UI enforces with grandfathering)
FREE_LIMITS = {
    "invitati_max": 20,
    "furnizori_max": 3,
    "checklist_personal_max": 10,
    "cheltuieli_max": 3,
}

PREMIUM_THEMES = ["gold_glamour", "burgundy_passion", "marble_modern", "forest_woodland", "dusty_rose"]
FREE_THEMES = ["ivory_elegant", "blush_romance", "sage_garden"]


@api.get("/billing/status")
async def billing_status(user=Depends(get_current_user)):
    """Returns the user's premium status + free-tier limits + sandbox flag."""
    _ensure_premium_defaults(user)
    return {
        "is_premium": bool(user.get("is_premium")),
        "premium_purchased_at": user.get("premium_purchased_at"),
        "premium_source": user.get("premium_source"),
        "free_limits": FREE_LIMITS,
        "premium_themes": PREMIUM_THEMES,
        "free_themes": FREE_THEMES,
        "sandbox": SANDBOX_BILLING,
        "product_id": "premium_lifetime",
        "default_price_string": "$6.99",
    }


@api.post("/billing/grant-mock")
async def billing_grant_mock(body: GrantMockPremiumIn, user=Depends(get_current_user)):
    """DEV/SANDBOX-ONLY: grants premium without real payment, for UX testing.
    In production, this endpoint is disabled; clients use /billing/verify-receipt instead."""
    if not SANDBOX_BILLING:
        raise HTTPException(status_code=403, detail="Sandbox mode disabled in production")
    if not body.confirm:
        raise HTTPException(status_code=400, detail="Confirmation required")
    await db.users.update_one(
        {"uid": user["uid"]},
        {"$set": {
            "is_premium": True,
            "premium_purchased_at": now_iso(),
            "premium_source": "mock",
        }},
    )
    return {"ok": True, "is_premium": True, "source": "mock"}


@api.post("/billing/revoke-mock")
async def billing_revoke_mock(user=Depends(get_current_user)):
    """DEV/SANDBOX-ONLY: revokes premium for re-testing the upgrade flow."""
    if not SANDBOX_BILLING:
        raise HTTPException(status_code=403, detail="Sandbox mode disabled in production")
    await db.users.update_one(
        {"uid": user["uid"]},
        {"$set": {**PREMIUM_FIELDS_DEFAULT}},
    )
    return {"ok": True, "is_premium": False}


@api.post("/billing/verify-receipt")
async def billing_verify_receipt(body: VerifyReceiptIn, user=Depends(get_current_user)):
    """PRODUCTION: verifies a Google Play / RevenueCat receipt and grants premium.

    For now in sandbox mode, this acts the same as grant-mock. In production, replace
    with real verification via RevenueCat REST API or Google Play Developer API.
    """
    if SANDBOX_BILLING:
        # Forward to mock handler logic
        await db.users.update_one(
            {"uid": user["uid"]},
            {"$set": {
                "is_premium": True,
                "premium_purchased_at": now_iso(),
                "premium_source": "sandbox",
                "revenuecat_user_id": body.revenuecat_user_id,
            }},
        )
        return {"ok": True, "is_premium": True, "source": "sandbox"}

    # ============ PRODUCTION PATH (RevenueCat REST API) ============
    rc_secret = os.environ.get("REVENUECAT_SECRET_KEY", "")
    if not rc_secret:
        raise HTTPException(status_code=503, detail="RevenueCat not configured")
    if not body.revenuecat_user_id:
        raise HTTPException(status_code=400, detail="revenuecat_user_id required")
    try:
        import httpx  # already in requirements
        async with httpx.AsyncClient(timeout=10.0) as cli:
            r = await cli.get(
                f"https://api.revenuecat.com/v1/subscribers/{body.revenuecat_user_id}",
                headers={"Authorization": f"Bearer {rc_secret}", "Accept": "application/json"},
            )
            if r.status_code != 200:
                raise HTTPException(status_code=502, detail=f"RC verify failed: {r.status_code}")
            data = r.json()
            entitlements = (data.get("subscriber") or {}).get("entitlements") or {}
            premium_ent = entitlements.get("premium_lifetime") or entitlements.get("premium")
            active = bool(premium_ent and premium_ent.get("expires_date") is None)  # lifetime
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"RC verify error: {e}")

    if active:
        await db.users.update_one(
            {"uid": user["uid"]},
            {"$set": {
                "is_premium": True,
                "premium_purchased_at": now_iso(),
                "premium_source": "revenuecat",
                "revenuecat_user_id": body.revenuecat_user_id,
            }},
        )
        return {"ok": True, "is_premium": True, "source": "revenuecat"}
    return {"ok": False, "is_premium": False, "reason": "no_active_entitlement"}


@api.post("/billing/restore")
async def billing_restore(user=Depends(get_current_user)):
    """Restore premium status: re-fetches RC entitlements (or returns current MongoDB state in sandbox)."""
    _ensure_premium_defaults(user)
    if SANDBOX_BILLING:
        # Sandbox: just return what's in DB
        return {
            "ok": True,
            "is_premium": bool(user.get("is_premium")),
            "source": user.get("premium_source"),
            "restored": False,  # nothing to restore in sandbox
        }
    # Production: re-verify via RC REST API using stored revenuecat_user_id
    rc_uid = user.get("revenuecat_user_id")
    if not rc_uid:
        return {"ok": True, "is_premium": False, "restored": False, "reason": "no_rc_id"}
    return await billing_verify_receipt(
        VerifyReceiptIn(revenuecat_user_id=rc_uid),
        user=user,
    )


@api.get("/assets/server-source", include_in_schema=False)
async def download_server_source():
    """Download latest backend source archive (v1.2.5)."""
    from fastapi.responses import FileResponse
    import os as _os, tarfile, tempfile
    # Build a fresh tar.gz from /app/backend on each request to always ship latest server.py
    src_files = ["/app/backend/server.py", "/app/backend/notifications.py", "/app/backend/requirements.txt", "/app/backend/render.yaml", "/app/backend/Dockerfile"]
    src_files = [f for f in src_files if _os.path.exists(f)]
    if not src_files:
        raise HTTPException(status_code=404, detail="Source files missing")
    out = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    out.close()
    with tarfile.open(out.name, "w:gz") as tar:
        for f in src_files:
            tar.add(f, arcname=f"backend/{_os.path.basename(f)}")
    return FileResponse(out.name, media_type="application/gzip", filename="nuntamea-backend-v1.2.5.tar.gz")


@api.get("/assets/server-py", include_in_schema=False)
async def download_server_py_only():
    """Download just the latest server.py (v1.2.5) — for quick replacement on Render."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/backend/server.py"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="server.py missing")
    return FileResponse(p, media_type="text/x-python; charset=utf-8", filename="server_v1.2.7.py")


@api.get("/assets/frontend-source", include_in_schema=False)
async def download_frontend_source():
    """Download full frontend source (without node_modules) as a tar.gz — v1.2.5."""
    from fastapi.responses import FileResponse
    import os as _os, tarfile, tempfile
    # Prefer pre-built v1.2.5 tarball
    for pre in ["/app/frontend_v1.2.6.tar.gz", "/app/frontend_v1.2.5.tar.gz", "/app/frontend_v1.2.4.tar.gz", "/app/frontend_v1.2.1.tar.gz"]:
        if _os.path.exists(pre):
            return FileResponse(pre, media_type="application/gzip", filename=_os.path.basename(pre).replace("frontend_", "nuntamea-frontend-"))
    # Fallback: build on the fly from /app/frontend
    fr_dir = "/app/frontend"
    if not _os.path.isdir(fr_dir):
        raise HTTPException(status_code=404, detail="Frontend folder missing")
    out = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    out.close()
    SKIP = {"node_modules", ".expo", "dist", ".git", ".metro-cache", ".cache", "web-build", "ios", "android"}
    def _filter(tarinfo):
        for s in SKIP:
            if f"/{s}/" in ("/" + tarinfo.name + "/") or tarinfo.name.endswith(f"/{s}"):
                return None
        return tarinfo
    with tarfile.open(out.name, "w:gz") as tar:
        tar.add(fr_dir, arcname="frontend", filter=_filter)
    return FileResponse(out.name, media_type="application/gzip", filename="nuntamea-frontend-v1.2.5.tar.gz")


@api.get("/assets/deploy-final", include_in_schema=False)
async def download_deploy_doc():
    """Download the final deploy markdown (release notes + build instructions)."""
    from fastapi.responses import FileResponse
    import os as _os
    # Prefer latest version
    for p in ["/app/DEPLOY_FINAL_v1.2.7.md", "/app/DEPLOY_FINAL_v1.2.6.md", "/app/DEPLOY_FINAL_v1.2.5.md", "/app/DEPLOY_FINAL_v1.2.4.md", "/app/DEPLOY_FINAL_v1.2.0.md", "/app/DEPLOY_FINAL_v1.1.0.md"]:
        if _os.path.exists(p):
            ver = _os.path.basename(p).replace("DEPLOY_FINAL_", "").replace(".md", "")
            return FileResponse(p, media_type="text/markdown; charset=utf-8", filename=f"DEPLOY_FINAL_{ver}.md")
    raise HTTPException(status_code=404, detail="Deploy doc missing")


@api.get("/assets/frontend-file", include_in_schema=False)
async def download_frontend_file(path: str):
    """Download any individual frontend file by relative path (e.g. ?path=app.json).
    Sandboxed to /app/frontend only.
    """
    from fastapi.responses import FileResponse
    import os as _os
    base = _os.path.realpath("/app/frontend")
    target = _os.path.realpath(_os.path.join(base, path))
    if not target.startswith(base + _os.sep) and target != base:
        raise HTTPException(status_code=400, detail="Invalid path")
    if not _os.path.exists(target) or not _os.path.isfile(target):
        raise HTTPException(status_code=404, detail=f"File not found: {path}")
    ext = _os.path.splitext(path)[1].lower()
    mime_map = {
        ".tsx": "text/plain; charset=utf-8", ".ts": "text/plain; charset=utf-8",
        ".jsx": "text/plain; charset=utf-8", ".js": "text/plain; charset=utf-8",
        ".json": "application/json; charset=utf-8",
        ".md": "text/markdown; charset=utf-8",
        ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".svg": "image/svg+xml", ".webp": "image/webp",
    }
    return FileResponse(target, media_type=mime_map.get(ext, "application/octet-stream"),
                        filename=_os.path.basename(target))


@api.get("/assets/frontend-zip-v126", include_in_schema=False)
async def download_frontend_zip_v126():
    """Download only the 18 v1.2.6 changed frontend files as a single ZIP — ready to extract into GitHub repo root."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend_v1.2.6_changed.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-v1.2.6-changed.zip")


@api.get("/assets/frontend-zip-v127", include_in_schema=False)
async def download_frontend_zip_v127():
    """Download the 11 v1.2.7 changed frontend files (bug-fix sprint) as a single ZIP."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend_v1.2.7_changed.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-v1.2.7-changed.zip")


@api.get("/assets/frontend-full-v128", include_in_schema=False)
async def download_frontend_full_v128():
    """Download the COMPLETE frontend code (v1.2.8) as a single ZIP — flat layout, ready for fresh GitHub repo + EAS build."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/nuntamea_frontend_FULL_v1.2.8.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-FULL-v1.2.8.zip")


@api.get("/assets/frontend-zip-v129", include_in_schema=False)
async def download_frontend_zip_v129():
    """Download v1.2.9 CHANGED files (10 files, bug fixes)."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend_v1.2.9_changed.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-v1.2.9-changed.zip")


@api.get("/assets/frontend-full-v129", include_in_schema=False)
async def download_frontend_full_v129():
    """Download COMPLETE frontend v1.2.9 — flat layout, ready for GitHub root + EAS build."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/nuntamea_frontend_FULL_v1.2.9.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-FULL-v1.2.9.zip")



@api.get("/assets/frontend-zip-v130", include_in_schema=False)
async def download_frontend_zip_v130():
    """Download v1.3.0 CHANGED files (5 files, final bug fixes before monetization)."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend_v1.3.0_changed.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-v1.3.0-changed.zip")


@api.get("/assets/frontend-full-v130", include_in_schema=False)
async def download_frontend_full_v130():
    """Download COMPLETE frontend v1.3.0 — flat layout, ready for GitHub root + EAS build."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/nuntamea_frontend_FULL_v1.3.0.zip"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ZIP missing")
    return FileResponse(p, media_type="application/zip", filename="nuntamea-frontend-FULL-v1.3.0.zip")



@api.get("/assets/manifest-v129", include_in_schema=False)
async def manifest_v129():
    """Return list of v1.2.9 changed frontend files with individual URLs."""
    files = [
        "app/(tabs)/invitati.tsx", "app/(tabs)/buget.tsx", "app/(tabs)/dashboard.tsx",
        "app/invitation/save-the-date.tsx",
        "src/i18n/index.ts", "src/i18n/ro.json", "src/i18n/en.json", "src/i18n/it.json", "src/i18n/es.json",
        "app.json",
    ]
    import os as _os
    base = "/api/assets/frontend-file?path="
    out = {"version": "1.2.9", "versionCode": 26, "buildNumber": "11", "totalFiles": len(files),
           "fullZipUrl": "/api/assets/frontend-full-v129",
           "changedZipUrl": "/api/assets/frontend-zip-v129",
           "files": []}
    for f in files:
        p = _os.path.join("/app/frontend", f)
        exists = _os.path.exists(p)
        out["files"].append({"path": f, "exists": exists, "size": _os.path.getsize(p) if exists else 0, "url": f"{base}{f}"})
    return out


@api.get("/assets/manifest-v127", include_in_schema=False)
async def manifest_v127():
    """Return list of v1.2.7 changed frontend files for individual GitHub upload."""
    files_v127 = [
        "src/pdfExport.ts",
        "app/invitation/share.tsx",
        "app/(tabs)/buget.tsx",
        "app/(tabs)/furnizori.tsx",
        "src/exporters.ts",
        "app/invitation/save-the-date.tsx",
        "src/i18n/ro.json",
        "src/i18n/en.json",
        "src/i18n/it.json",
        "src/i18n/es.json",
        "app.json",
    ]
    import os as _os
    base = "/api/assets/frontend-file?path="
    out = {"version": "1.2.7", "versionCode": 21, "buildNumber": "7", "totalFiles": len(files_v127), "zipUrl": "/api/assets/frontend-zip-v127", "files": []}
    for f in files_v127:
        p = _os.path.join("/app/frontend", f)
        exists = _os.path.exists(p)
        out["files"].append({"path": f, "exists": exists, "size": _os.path.getsize(p) if exists else 0, "url": f"{base}{f}"})
    return out


@api.get("/assets/manifest-v126", include_in_schema=False)
async def manifest_v126():
    """Return list of v1.2.6 changed frontend files for individual GitHub upload."""
    files_v126 = [
        # P0: Premium badge + Premium UX
        "src/PremiumUpgradeModal.tsx",
        # P0: Routing + language
        "app/index.tsx",
        "app/language-select.tsx",
        "src/i18n/LanguageContext.tsx",
        "src/i18n/index.ts",
        # P0/P1: Legal screens fully i18n
        "app/legal/index.tsx",
        "app/legal/privacy.tsx",
        "app/legal/terms.tsx",
        # P1: Cookie banner i18n
        "src/CookieBanner.tsx",
        # P1: Vendors layout
        "app/(tabs)/furnizori.tsx",
        # P1: Currency placeholder + format
        "app/(tabs)/dashboard.tsx",
        "app/(tabs)/buget.tsx",
        # P1: Invitation date locale
        "app/invitation/overview.tsx",
        # i18n JSON dictionaries (all 4 langs)
        "src/i18n/ro.json",
        "src/i18n/en.json",
        "src/i18n/it.json",
        "src/i18n/es.json",
        # Version bump
        "app.json",
    ]
    import os as _os
    base = "/api/assets/frontend-file?path="
    out = {"version": "1.2.6", "versionCode": 20, "buildNumber": "6", "totalFiles": len(files_v126), "files": []}
    for f in files_v126:
        p = _os.path.join("/app/frontend", f)
        exists = _os.path.exists(p)
        out["files"].append({
            "path": f,
            "exists": exists,
            "size": _os.path.getsize(p) if exists else 0,
            "url": f"{base}{f}",
        })
    return out



@api.get("/assets/locale-ro", include_in_schema=False)
async def download_locale_ro():
    """Download the source-of-truth ro.json (all 758 keys) for external translation."""
    from fastapi.responses import FileResponse
    import os as _os
    p = "/app/frontend/src/i18n/ro.json"
    if not _os.path.exists(p):
        raise HTTPException(status_code=404, detail="ro.json missing")
    return FileResponse(p, media_type="application/json; charset=utf-8", filename="ro.json")


@api.get("/assets/locale-template", include_in_schema=False)
async def download_locale_template():
    """Download a tar.gz with all 4 locale files (ro source + en/it/es with RO placeholders)
    and a translation README explaining what's new."""
    from fastapi.responses import FileResponse
    import os as _os, tarfile, tempfile
    src = "/app/frontend/src/i18n"
    files = ["ro.json", "en.json", "it.json", "es.json"]
    out = tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False)
    out.close()
    with tarfile.open(out.name, "w:gz") as tar:
        for f in files:
            full = _os.path.join(src, f)
            if _os.path.exists(full):
                tar.add(full, arcname=f"locales/{f}")
        # Add a README with translation instructions
        readme_path = "/app/TRANSLATION_README_v1.1.0.md"
        if _os.path.exists(readme_path):
            tar.add(readme_path, arcname="TRANSLATION_README.md")
    return FileResponse(out.name, media_type="application/gzip", filename="nuntamea-locales-v1.1.0.tar.gz")


def _render_not_found() -> str:
    return """<!DOCTYPE html>
<html lang="ro"><head><meta charset="UTF-8"><title>Invitație inexistentă</title>
<style>body{font-family:-apple-system,sans-serif;text-align:center;padding:80px 20px;background:#FFF8F5;color:#2d2d2d}h1{color:#E8789A}</style>
</head><body><h1>Invitație inexistentă 💔</h1><p>Link-ul pe care l-ai accesat nu mai este valid.</p></body></html>"""


# ---------- Public Invitation Renderer (8 themes, multilingual) ----------
import urllib.parse as _urlparse

# Language-specific UI strings used inside the public invitation HTML
INV_I18N = {
    "ro": {
        "title": "Invitație nuntă",
        "intro": "Ne-ar face mare bucurie să ne fii alături<br/>în cea mai importantă zi a vieții noastre.",
        "intro_short": "Cu multă bucurie te invităm",
        "godparents": "Nași",
        "parents_groom": "Părinții mirelui",
        "parents_bride": "Părinții miresei",
        "view_map": "Vezi pe hartă",
        "rsvp_q": "Dragă <strong>{name}</strong>,<br/>ne onorezi cu prezența?",
        "yes": "✓ Vin cu drag!",
        "no": "✗ Nu pot veni",
        "submitting": "Se trimite...",
        "thanks_yes": "Ne bucurăm! Te așteptăm! 🎊",
        "thanks_no": "Îți mulțumim că ne-ai anunțat! 💕",
        "err": "A apărut o eroare. Te rugăm să încerci din nou.",
        "footer": "NUNTA MEA",
        "save_date": "SAVE THE DATE",
        "ceremony": "CEREMONIA",
        "months": ["ianuarie","februarie","martie","aprilie","mai","iunie","iulie","august","septembrie","octombrie","noiembrie","decembrie"],
        "weekdays": ["luni","marți","miercuri","joi","vineri","sâmbătă","duminică"],
    },
    "en": {
        "title": "Wedding Invitation",
        "intro": "It would be our greatest joy to have you<br/>by our side on the most important day of our lives.",
        "intro_short": "We joyfully invite you",
        "godparents": "Godparents",
        "parents_groom": "Groom's parents",
        "parents_bride": "Bride's parents",
        "view_map": "Open in maps",
        "rsvp_q": "Dear <strong>{name}</strong>,<br/>will you join us?",
        "yes": "✓ I'll be there!",
        "no": "✗ I can't make it",
        "submitting": "Sending...",
        "thanks_yes": "We're so happy! See you soon! 🎊",
        "thanks_no": "Thank you for letting us know 💕",
        "err": "Something went wrong. Please try again.",
        "footer": "MY WEDDING",
        "save_date": "SAVE THE DATE",
        "ceremony": "CEREMONY",
        "months": ["January","February","March","April","May","June","July","August","September","October","November","December"],
        "weekdays": ["Monday","Tuesday","Wednesday","Thursday","Friday","Saturday","Sunday"],
    },
    "it": {
        "title": "Invito di nozze",
        "intro": "Sarebbe una grande gioia averti accanto<br/>nel giorno più importante della nostra vita.",
        "intro_short": "Ti invitiamo con gioia",
        "godparents": "Testimoni",
        "parents_groom": "Genitori dello sposo",
        "parents_bride": "Genitori della sposa",
        "view_map": "Vedi sulla mappa",
        "rsvp_q": "Caro/a <strong>{name}</strong>,<br/>parteciperai?",
        "yes": "✓ Ci sarò!",
        "no": "✗ Non posso venire",
        "submitting": "Invio in corso...",
        "thanks_yes": "Siamo felicissimi! Ti aspettiamo! 🎊",
        "thanks_no": "Grazie per averci avvisato 💕",
        "err": "Si è verificato un errore. Riprova.",
        "footer": "IL MIO MATRIMONIO",
        "save_date": "SAVE THE DATE",
        "ceremony": "CERIMONIA",
        "months": ["gennaio","febbraio","marzo","aprile","maggio","giugno","luglio","agosto","settembre","ottobre","novembre","dicembre"],
        "weekdays": ["lunedì","martedì","mercoledì","giovedì","venerdì","sabato","domenica"],
    },
    "es": {
        "title": "Invitación de boda",
        "intro": "Sería nuestra mayor alegría tenerte<br/>a nuestro lado en el día más importante de nuestras vidas.",
        "intro_short": "Te invitamos con alegría",
        "godparents": "Padrinos",
        "parents_groom": "Padres del novio",
        "parents_bride": "Padres de la novia",
        "view_map": "Ver en el mapa",
        "rsvp_q": "Querido/a <strong>{name}</strong>,<br/>¿nos acompañarás?",
        "yes": "✓ ¡Allí estaré!",
        "no": "✗ No puedo asistir",
        "submitting": "Enviando...",
        "thanks_yes": "¡Qué alegría! ¡Te esperamos! 🎊",
        "thanks_no": "Gracias por avisarnos 💕",
        "err": "Algo salió mal. Por favor, inténtalo de nuevo.",
        "footer": "MI BODA",
        "save_date": "SAVE THE DATE",
        "ceremony": "CEREMONIA",
        "months": ["enero","febrero","marzo","abril","mayo","junio","julio","agosto","septiembre","octubre","noviembre","diciembre"],
        "weekdays": ["lunes","martes","miércoles","jueves","viernes","sábado","domingo"],
    },
}

# Theme palettes — must match frontend src/invitationThemes.ts
THEME_DATA = {
    "ivory_elegant":    {"bg":"#FDF8F2","card":"#FFFFFF","accent":"#C9A96E","accentSoft":"#F4EBD8","text":"#3A2E1F","muted":"#8A7A66","divider":"#E8DDC7","layout":"classic","grad_top":"#FDF8F2","grad_bot":"#F4EBD8"},
    "blush_romance":    {"bg":"#FFF0F3","card":"#FFFFFF","accent":"#C28B98","accentSoft":"#FAD7DF","text":"#3D1F2A","muted":"#8A6975","divider":"#F1D0D9","layout":"classic","grad_top":"#FFF0F3","grad_bot":"#FAD7DF"},
    "sage_garden":      {"bg":"#F8FBF5","card":"#FFFFFF","accent":"#87A878","accentSoft":"#DCE7D2","text":"#293125","muted":"#6B7866","divider":"#D2DEC6","layout":"classic","grad_top":"#F8FBF5","grad_bot":"#DCE7D2"},
    "gold_glamour":     {"bg":"#FBF6EC","card":"#FFFDF7","accent":"#B8862F","accentSoft":"#F2E5C5","text":"#2A1F0F","muted":"#7A6840","divider":"#E5D5A8","layout":"ornate","grad_top":"#FBF6EC","grad_bot":"#F2E5C5"},
    "burgundy_passion": {"bg":"#3D1620","card":"#4F1A28","accent":"#E8C8A8","accentSoft":"#5C2230","text":"#FAEDE0","muted":"#D8B5A0","divider":"#7C3A4A","layout":"luxe","grad_top":"#3D1620","grad_bot":"#5C2230"},
    "marble_modern":    {"bg":"#F2F1ED","card":"#FFFFFF","accent":"#1F1D1A","accentSoft":"#E5E2DA","text":"#1F1D1A","muted":"#7C7268","divider":"#1F1D1A","layout":"magazine","grad_top":"#F2F1ED","grad_bot":"#E5E2DA"},
    "forest_woodland":  {"bg":"#1F2D1E","card":"#26392A","accent":"#D4B872","accentSoft":"#3B5238","text":"#F2EAD3","muted":"#B5C2A7","divider":"#5A7456","layout":"botanical","grad_top":"#1F2D1E","grad_bot":"#26392A"},
    "dusty_rose":       {"bg":"#FAF1ED","card":"#FFFAF7","accent":"#A0656D","accentSoft":"#EBD0D3","text":"#34201F","muted":"#7B585A","divider":"#DFC1C4","layout":"vintage","grad_top":"#FAF1ED","grad_bot":"#EBD0D3"},
}

# Backward-compat for legacy theme keys
_THEME_LEGACY = {"burgundy_velvet":"burgundy_passion","marble_white":"marble_modern","forest_green":"forest_woodland"}


def _format_invitation_date(iso: str, lang: str) -> tuple[str, str, str]:
    """Returns (long, short, weekday) localized date strings."""
    if not iso:
        return "", "", ""
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        L = INV_I18N.get(lang, INV_I18N["ro"])
        long_d = f"{dt.day} {L['months'][dt.month - 1]} {dt.year}"
        short_d = f"{dt.day:02d}.{dt.month:02d}.{dt.year}"
        # Python weekday(): Mon=0..Sun=6. We have monday-first list.
        wd = L["weekdays"][dt.weekday()] if 0 <= dt.weekday() < 7 else ""
        return long_d, short_d, wd
    except Exception:
        return iso, iso, ""


def _maps_url(addr: str, harta_url: str = "") -> str:
    if harta_url:
        return harta_url
    if not addr:
        return ""
    return f"https://www.google.com/maps/search/?api=1&query={_urlparse.quote(addr)}"


def _build_locations_block(locations: list, palette: dict, L: dict) -> str:
    """Builds the locations list HTML — shared across themes (CSS varies)."""
    if not locations:
        return ""
    out = []
    for loc in locations:
        if not (loc.get("eveniment") or loc.get("locatie")):
            continue
        ora = loc.get("ora", "") or ""
        ev = loc.get("eveniment", "") or ""
        locatie = loc.get("locatie", "") or ""
        adresa = loc.get("adresa", "") or ""
        harta = loc.get("harta_url", "") or ""
        map_link = _maps_url(adresa, harta)
        map_btn = f'<a class="loc-map" href="{map_link}" target="_blank" rel="noopener">📍 {L["view_map"]}</a>' if map_link else ""
        out.append(f"""
            <div class="loc">
              <div class="loc-time">{ora}</div>
              <div class="loc-event">{ev}</div>
              {f'<div class="loc-place">{locatie}</div>' if locatie else ''}
              {f'<div class="loc-addr">{adresa}</div>' if adresa else ''}
              {map_btn}
            </div>""")
    return "\n".join(out)


def _build_family_block(setup: dict, L: dict) -> str:
    """Nași + parents block — shared HTML, theme-styled via CSS."""
    parts = []
    nas = (setup.get("nas") or "").strip()
    nasa = (setup.get("nasa") or "").strip()
    if nas or nasa:
        nasi = " & ".join([x for x in [nasa, nas] if x])
        parts.append(f"<div class='fam-row'><span class='fam-label'>{L['godparents']}</span><span class='fam-val'>{nasi}</span></div>")
    tm = (setup.get("tata_mire") or "").strip()
    mm = (setup.get("mama_mire") or "").strip()
    if tm or mm:
        pg = " & ".join([x for x in [tm, mm] if x])
        parts.append(f"<div class='fam-row'><span class='fam-label'>{L['parents_groom']}</span><span class='fam-val'>{pg}</span></div>")
    tmi = (setup.get("tata_mireasa") or "").strip()
    mmi = (setup.get("mama_mireasa") or "").strip()
    if tmi or mmi:
        pb = " & ".join([x for x in [tmi, mmi] if x])
        parts.append(f"<div class='fam-row'><span class='fam-label'>{L['parents_bride']}</span><span class='fam-val'>{pb}</span></div>")
    if not parts:
        return ""
    return f"<div class='family'>{''.join(parts)}</div>"


def _photo_block(photo: str, layout: str) -> str:
    if photo:
        return f'<img src="{photo}" alt="" class="couple-photo" />'
    # Fallback ornament per layout
    icons = {"ornate": "❦", "luxe": "✦", "magazine": "—", "botanical": "✿", "vintage": "♥"}
    return f'<div class="heart">{icons.get(layout, "💕")}</div>'


def _rsvp_block(code: str, guest_nume: str, status: str, L: dict) -> str:
    if status == "confirmat":
        return f'<div class="rsvp-done confirmed">{L["thanks_yes"]}</div>'
    if status == "refuzat":
        return f'<div class="rsvp-done declined">{L["thanks_no"]}</div>'
    q = L["rsvp_q"].format(name=guest_nume)
    return f'''
        <p class="rsvp-q">{q}</p>
        <button class="btn-yes" onclick="rsvp('confirmat')">{L["yes"]}</button>
        <button class="btn-no" onclick="rsvp('refuzat')">{L["no"]}</button>
        <div id="submitting" style="display:none;margin-top:12px;color:#888">{L["submitting"]}</div>
        '''


def _theme_css(palette: dict, layout: str) -> str:
    """Returns layout-specific CSS using palette colors."""
    P = palette
    base = f"""
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ font-family: 'Playfair Display', Georgia, serif; background: linear-gradient(180deg, {P['grad_top']} 0%, {P['grad_bot']} 100%); color: {P['text']}; min-height: 100vh; padding: 24px 16px; -webkit-font-smoothing: antialiased; }}
  a {{ color: inherit; text-decoration: none; }}
  .card {{ max-width: 480px; margin: 0 auto; background: {P['card']}; border-radius: 24px; box-shadow: 0 12px 40px rgba(0,0,0,0.10); overflow: hidden; }}
  .hero {{ position: relative; width: 100%; aspect-ratio: 3/4; background: {P['accentSoft']}; display: flex; align-items: center; justify-content: center; overflow: hidden; }}
  .couple-photo {{ width: 100%; height: 100%; object-fit: cover; }}
  .heart {{ font-size: 120px; opacity: 0.55; color: {P['accent']}; }}
  .body {{ padding: 32px 28px 40px; text-align: center; font-family: 'Inter', sans-serif; }}
  .intro {{ font-size: 15px; color: {P['muted']}; line-height: 1.7; margin-bottom: 22px; }}
  .family {{ margin: 0 0 18px; padding: 16px; border-radius: 12px; background: {P['accentSoft']}33; }}
  .fam-row {{ display: flex; flex-direction: column; gap: 2px; padding: 6px 0; }}
  .fam-label {{ font-size: 11px; letter-spacing: 2px; text-transform: uppercase; color: {P['muted']}; }}
  .fam-val {{ font-family: 'Playfair Display', serif; font-size: 15px; color: {P['text']}; }}
  .loc {{ border-top: 1px solid {P['divider']}55; padding: 18px 0; }}
  .loc:last-of-type {{ border-bottom: 1px solid {P['divider']}55; margin-bottom: 24px; }}
  .loc-time {{ font-family: 'Playfair Display', serif; font-size: 22px; color: {P['accent']}; font-style: italic; }}
  .loc-event {{ font-size: 15px; font-weight: 600; color: {P['text']}; margin-top: 4px; }}
  .loc-place {{ font-size: 13px; color: {P['muted']}; margin-top: 2px; }}
  .loc-addr {{ font-size: 12px; color: {P['muted']}; margin-top: 2px; opacity: 0.85; }}
  .loc-map {{ display: inline-block; margin-top: 8px; padding: 6px 12px; border: 1px solid {P['accent']}; border-radius: 999px; font-size: 12px; color: {P['accent']}; font-weight: 600; }}
  .rsvp-q {{ font-family: 'Playfair Display', serif; font-size: 20px; color: {P['text']}; margin-top: 24px; margin-bottom: 18px; line-height: 1.5; }}
  .btn-yes, .btn-no {{ display: block; width: 100%; padding: 16px; border: none; border-radius: 12px; font-size: 16px; font-weight: 600; cursor: pointer; margin-bottom: 10px; font-family: 'Inter', sans-serif; -webkit-tap-highlight-color: transparent; transition: transform 0.1s; }}
  .btn-yes {{ background: {P['accent']}; color: #fff; }}
  .btn-yes:active {{ transform: scale(0.97); }}
  .btn-no {{ background: transparent; color: {P['muted']}; border: 1.5px solid {P['divider']}; }}
  .btn-no:active {{ transform: scale(0.97); }}
  .rsvp-done {{ padding: 22px; border-radius: 12px; font-family: 'Playfair Display', serif; font-size: 19px; }}
  .rsvp-done.confirmed {{ background: {P['accentSoft']}; color: {P['text']}; }}
  .rsvp-done.declined {{ background: {P['divider']}66; color: {P['text']}; }}
  .footer {{ text-align: center; margin-top: 24px; font-size: 11px; color: {P['muted']}; font-family: 'Inter', sans-serif; letter-spacing: 3px; opacity: 0.7; }}
  /* hero overlay for legibility (classic + vintage) */
  .hero::after {{ content: ''; position: absolute; inset: 0; background: linear-gradient(180deg, transparent 50%, rgba(0,0,0,0.55) 100%); }}
  .hero-text {{ position: absolute; bottom: 30px; left: 0; right: 0; text-align: center; color: #fff; z-index: 2; padding: 0 20px; }}
  .hero-names {{ font-size: 34px; font-weight: 400; line-height: 1.2; letter-spacing: 1px; text-shadow: 0 2px 12px rgba(0,0,0,0.4); }}
  .hero-names .amp {{ color: {P['accentSoft']}; font-style: italic; padding: 0 8px; }}
  .hero-date {{ font-size: 13px; letter-spacing: 3px; margin-top: 10px; font-family: 'Inter', sans-serif; opacity: 0.95; }}
"""

    # Per-layout extras
    if layout == "ornate":  # Gold — Art Deco
        extra = f"""
  body {{ background: {P['bg']}; }}
  .card {{ border: 1px solid {P['accent']}55; box-shadow: 0 0 0 8px {P['card']}, 0 0 0 9px {P['accent']}55, 0 12px 40px rgba(184,134,47,0.18); margin-top: 20px; margin-bottom: 20px; }}
  .deco-top, .deco-bot {{ height: 28px; background-image: linear-gradient(135deg, transparent 49%, {P['accent']} 49%, {P['accent']} 51%, transparent 51%), linear-gradient(45deg, transparent 49%, {P['accent']} 49%, {P['accent']} 51%, transparent 51%); background-size: 18px 18px; opacity: 0.5; }}
  .deco-bot {{ transform: rotate(180deg); }}
  .body {{ padding: 30px 32px 36px; }}
  .monogram {{ font-family: 'Playfair Display', serif; font-style: italic; font-size: 56px; color: {P['accent']}; margin: -6px 0 8px; line-height: 1; letter-spacing: -2px; }}
  .label-tiny {{ font-size: 10px; letter-spacing: 6px; color: {P['accent']}; text-transform: uppercase; margin-bottom: 16px; }}
  .save-date-tag {{ display: inline-block; padding: 6px 18px; border: 1px solid {P['accent']}; border-radius: 999px; font-size: 10px; letter-spacing: 4px; color: {P['accent']}; margin-bottom: 14px; }}
  .names-deco {{ font-family: 'Playfair Display', serif; font-size: 30px; color: {P['text']}; margin: 8px 0 10px; line-height: 1.15; }}
  .names-deco .amp {{ color: {P['accent']}; font-style: italic; padding: 0 10px; font-size: 36px; }}
  .date-row {{ display: flex; justify-content: center; align-items: center; gap: 16px; margin: 14px 0 24px; }}
  .date-row .num {{ font-family: 'Playfair Display', serif; font-size: 36px; color: {P['accent']}; line-height: 1; }}
  .date-row .lbl {{ font-size: 9px; letter-spacing: 2px; color: {P['muted']}; text-transform: uppercase; margin-top: 4px; }}
  .date-sep {{ width: 1px; height: 36px; background: {P['accent']}55; }}
  .ornament-row {{ display: flex; align-items: center; gap: 12px; margin: 18px 0; }}
  .ornament-row .line {{ flex: 1; height: 1px; background: {P['accent']}55; }}
  .ornament-row .dot {{ width: 6px; height: 6px; border-radius: 50%; background: {P['accent']}; transform: rotate(45deg); }}
  .hero {{ aspect-ratio: 4/5; }}
  .hero-text {{ display: none; }}
  .hero::after {{ display: none; }}
"""
    elif layout == "luxe":  # Burgundy — Victorian / dark velvet
        extra = f"""
  body {{ background: radial-gradient(ellipse at top, {P['accentSoft']}, {P['bg']} 70%); padding: 32px 16px 40px; }}
  .card {{ border: 1px solid {P['divider']}; box-shadow: 0 30px 80px rgba(0,0,0,0.55); position: relative; }}
  .card::before {{ content: ''; position: absolute; inset: 12px; border: 1px solid {P['accent']}55; border-radius: 14px; pointer-events: none; }}
  .eyebrow {{ display: inline-block; padding: 4px 14px; border: 1px solid {P['accent']}; border-radius: 0; font-size: 10px; letter-spacing: 6px; color: {P['accent']}; text-transform: uppercase; margin-bottom: 22px; }}
  .body {{ padding: 40px 32px 40px; color: {P['text']}; }}
  .intro {{ color: {P['muted']}; font-style: italic; }}
  .luxe-names {{ font-family: 'Playfair Display', serif; font-size: 38px; color: {P['accent']}; margin: 8px 0 6px; letter-spacing: 1px; }}
  .luxe-and {{ display: block; font-style: italic; font-size: 14px; color: {P['muted']}; letter-spacing: 4px; margin: 6px 0; }}
  .luxe-divider {{ width: 60px; height: 2px; background: {P['accent']}; margin: 20px auto; }}
  .luxe-date {{ font-family: 'Playfair Display', serif; font-size: 22px; color: {P['text']}; letter-spacing: 2px; }}
  .luxe-weekday {{ font-size: 11px; letter-spacing: 4px; color: {P['muted']}; text-transform: uppercase; margin-top: 6px; }}
  .family {{ background: {P['accentSoft']}33; border: 1px solid {P['divider']}55; }}
  .family .fam-label {{ color: {P['accent']}; }}
  .loc-event {{ color: {P['accent']}; letter-spacing: 1px; text-transform: uppercase; font-size: 13px; }}
  .btn-no {{ color: {P['accent']}; border-color: {P['accent']}55; background: transparent; }}
  .hero {{ display: none; }}
  .photo-luxe {{ width: 200px; height: 240px; margin: 0 auto 18px; border-radius: 4px; overflow: hidden; border: 1px solid {P['accent']}55; box-shadow: 0 12px 30px rgba(0,0,0,0.4); }}
  .photo-luxe img {{ width: 100%; height: 100%; object-fit: cover; }}
  .photo-luxe-fallback {{ width: 200px; height: 240px; margin: 0 auto 18px; display: flex; align-items: center; justify-content: center; background: {P['accentSoft']}; color: {P['accent']}; font-size: 60px; }}
"""
    elif layout == "magazine":  # Marble — Editorial
        extra = f"""
  body {{ background: {P['bg']}; padding: 0; }}
  .card {{ max-width: 520px; border-radius: 0; box-shadow: none; background: {P['card']}; }}
  .mag-header {{ padding: 24px 28px 0; display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 2px solid {P['text']}; padding-bottom: 18px; }}
  .mag-header .iss {{ font-size: 10px; letter-spacing: 3px; color: {P['muted']}; text-transform: uppercase; font-family: 'Inter', sans-serif; }}
  .mag-header .iss strong {{ color: {P['text']}; }}
  .mag-hero {{ position: relative; aspect-ratio: 1/1; overflow: hidden; background: {P['accentSoft']}; }}
  .mag-hero img {{ width: 100%; height: 100%; object-fit: cover; filter: grayscale(8%) contrast(1.05); }}
  .mag-hero-fallback {{ width: 100%; height: 100%; display: flex; align-items: center; justify-content: center; font-size: 90px; color: {P['accent']}; }}
  .mag-numbers {{ display: grid; grid-template-columns: 1fr 1fr; gap: 0; padding: 0; border-bottom: 1px solid {P['text']}; }}
  .mag-num-cell {{ padding: 28px 24px; border-right: 1px solid {P['text']}; }}
  .mag-num-cell:last-child {{ border-right: none; }}
  .mag-num {{ font-family: 'Playfair Display', serif; font-size: 64px; line-height: 1; color: {P['text']}; font-weight: 400; }}
  .mag-lbl {{ font-size: 9px; letter-spacing: 3px; color: {P['muted']}; text-transform: uppercase; margin-top: 8px; font-family: 'Inter', sans-serif; }}
  .body {{ padding: 32px 28px 40px; text-align: left; }}
  .mag-eyebrow {{ font-size: 10px; letter-spacing: 4px; color: {P['muted']}; text-transform: uppercase; margin-bottom: 8px; }}
  .mag-names {{ font-family: 'Playfair Display', serif; font-size: 56px; line-height: 0.95; color: {P['text']}; font-weight: 400; letter-spacing: -2px; margin-bottom: 4px; }}
  .mag-names .amp {{ font-style: italic; color: {P['muted']}; font-size: 40px; padding: 0 4px; }}
  .mag-rule {{ width: 32px; height: 2px; background: {P['text']}; margin: 18px 0; }}
  .intro {{ text-align: left; font-size: 14px; line-height: 1.65; }}
  .family {{ background: transparent; border-top: 1px solid {P['divider']}66; border-radius: 0; padding: 16px 0; }}
  .fam-row {{ flex-direction: row; justify-content: space-between; align-items: baseline; padding: 4px 0; }}
  .fam-label {{ font-size: 10px; }}
  .loc {{ text-align: left; }}
  .loc-time {{ font-style: normal; }}
  .loc-event {{ text-transform: uppercase; letter-spacing: 2px; font-size: 12px; }}
  .rsvp-q {{ text-align: left; font-size: 22px; }}
  .footer {{ text-align: left; margin: 24px 28px 16px; padding-top: 16px; border-top: 1px solid {P['divider']}66; }}
"""
    elif layout == "botanical":  # Forest — leaves
        extra = f"""
  body {{ background: {P['bg']}; }}
  body::before {{ content: ''; position: fixed; inset: 0; background-image: radial-gradient(circle at 10% 5%, {P['accentSoft']}55 0%, transparent 30%), radial-gradient(circle at 90% 95%, {P['accentSoft']}55 0%, transparent 35%); pointer-events: none; z-index: 0; }}
  .card {{ position: relative; border: 1px solid {P['divider']}; }}
  .leaf-svg {{ position: absolute; opacity: 0.45; pointer-events: none; }}
  .leaf-tl {{ top: -10px; left: -10px; width: 110px; transform: rotate(-25deg); }}
  .leaf-br {{ bottom: -10px; right: -10px; width: 130px; transform: rotate(155deg); }}
  .body {{ padding: 36px 28px 40px; color: {P['text']}; position: relative; z-index: 1; }}
  .bot-monogram {{ font-family: 'Playfair Display', serif; font-style: italic; font-size: 80px; color: {P['accent']}; line-height: 0.9; margin: -8px 0 8px; letter-spacing: -3px; }}
  .bot-eyebrow {{ font-size: 10px; letter-spacing: 5px; color: {P['accent']}; text-transform: uppercase; margin-bottom: 10px; }}
  .bot-names {{ font-family: 'Playfair Display', serif; font-size: 30px; color: {P['text']}; margin: 6px 0 12px; line-height: 1.2; }}
  .bot-names .amp {{ font-style: italic; color: {P['accent']}; padding: 0 6px; }}
  .bot-leaf-rule {{ display: flex; align-items: center; gap: 10px; margin: 20px 0; color: {P['accent']}; }}
  .bot-leaf-rule .line {{ flex: 1; height: 1px; background: {P['accent']}66; }}
  .intro {{ color: {P['muted']}; }}
  .family {{ background: {P['accentSoft']}55; border-radius: 16px; }}
  .fam-label {{ color: {P['accent']}; }}
  .loc {{ border-color: {P['accent']}55; }}
  .loc:last-of-type {{ border-color: {P['accent']}55; }}
  .loc-time {{ color: {P['accent']}; }}
  .loc-map {{ background: {P['accent']}; color: {P['bg']}; border-color: {P['accent']}; }}
  .btn-no {{ color: {P['accentSoft']}; border-color: {P['accentSoft']}77; }}
  .footer {{ color: {P['accent']}; }}
  .hero {{ display: none; }}
  .photo-bot {{ width: 220px; height: 220px; border-radius: 50%; margin: 0 auto 20px; overflow: hidden; border: 3px solid {P['accent']}; box-shadow: 0 12px 28px rgba(0,0,0,0.3); }}
  .photo-bot img {{ width: 100%; height: 100%; object-fit: cover; }}
  .photo-bot-fallback {{ width: 220px; height: 220px; border-radius: 50%; margin: 0 auto 20px; background: {P['accentSoft']}; display: flex; align-items: center; justify-content: center; font-size: 80px; color: {P['accent']}; border: 3px solid {P['accent']}; }}
"""
    elif layout == "vintage":  # Dusty Rose — boho watercolor
        extra = f"""
  body {{ background: linear-gradient(180deg, {P['bg']} 0%, {P['accentSoft']}88 100%); }}
  .card {{ border-radius: 36px; border: 1px solid {P['divider']}; position: relative; overflow: visible; }}
  .card::before {{ content: ''; position: absolute; top: -20px; left: 50%; transform: translateX(-50%); width: 80px; height: 80px; background: radial-gradient(circle, {P['accent']}55 0%, transparent 70%); pointer-events: none; }}
  .vint-floral {{ width: 100px; height: 100px; margin: 18px auto -8px; opacity: 0.7; }}
  .body {{ padding: 8px 28px 38px; }}
  .vint-eyebrow {{ font-family: 'Playfair Display', serif; font-style: italic; font-size: 13px; color: {P['accent']}; letter-spacing: 4px; text-transform: uppercase; margin: 6px 0 4px; }}
  .vint-names {{ font-family: 'Playfair Display', serif; font-size: 38px; line-height: 1.05; color: {P['accent']}; margin: 4px 0 6px; }}
  .vint-names .amp {{ font-style: italic; color: {P['muted']}; font-size: 28px; padding: 0 6px; }}
  .vint-ribbon {{ display: inline-block; background: {P['accent']}; color: #fff; padding: 6px 22px; font-family: 'Playfair Display', serif; font-style: italic; font-size: 13px; letter-spacing: 2px; border-radius: 999px; margin: 10px 0 18px; box-shadow: 0 6px 14px {P['accent']}55; }}
  .intro {{ font-style: italic; }}
  .family {{ background: {P['accentSoft']}55; border-radius: 20px; }}
  .loc {{ border-color: {P['accent']}33; }}
  .hero {{ display: none; }}
  .photo-vint {{ width: 180px; height: 220px; margin: 18px auto 10px; border-radius: 999px; overflow: hidden; border: 3px solid {P['accent']}33; box-shadow: 0 12px 24px {P['accent']}22; }}
  .photo-vint img {{ width: 100%; height: 100%; object-fit: cover; }}
  .photo-vint-fallback {{ width: 180px; height: 220px; margin: 18px auto 10px; border-radius: 999px; background: {P['accentSoft']}; display: flex; align-items: center; justify-content: center; font-size: 60px; color: {P['accent']}; border: 3px solid {P['accent']}33; }}
"""
    else:  # classic (Ivory, Blush, Sage)
        extra = ""

    return base + extra


# Reusable SVG snippets
_LEAF_SVG = '''<svg class="leaf-svg leaf-tl" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M30 170 Q70 90 170 30 Q150 110 60 180 Z" fill="currentColor"/><path d="M70 130 L100 100 M50 150 L80 120" stroke="#1F2D1E" stroke-width="1.5" opacity="0.4"/></svg>'''
_LEAF_SVG_BR = '''<svg class="leaf-svg leaf-br" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg"><path d="M30 170 Q70 90 170 30 Q150 110 60 180 Z" fill="currentColor"/><path d="M70 130 L100 100 M50 150 L80 120" stroke="#1F2D1E" stroke-width="1.5" opacity="0.4"/></svg>'''
_FLORAL_SVG = '''<svg class="vint-floral" viewBox="0 0 100 100" xmlns="http://www.w3.org/2000/svg"><g fill="currentColor"><circle cx="50" cy="30" r="8"/><circle cx="35" cy="45" r="7"/><circle cx="65" cy="45" r="7"/><circle cx="50" cy="55" r="6"/><circle cx="42" cy="62" r="5"/><circle cx="58" cy="62" r="5"/></g><path d="M50 65 Q40 78 35 90 M50 65 Q60 78 65 90 M50 65 L50 92" stroke="currentColor" stroke-width="1.5" fill="none" opacity="0.7"/></svg>'''


def _render_layout_classic(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    return f"""
    <div class="hero">
      {_photo_block(photo, layout)}
      <div class="hero-text">
        <div class="hero-names">{mireasa} <span class="amp">&</span> {mire}</div>
        {f'<div class="hero-date">{data_long.upper()}</div>' if data_long else ''}
      </div>
    </div>
    <div class="body">
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>"""


def _render_layout_ornate(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    parts = data_short.split(".") if data_short else ["","",""]
    day = parts[0] if len(parts) > 0 else ""
    month = parts[1] if len(parts) > 1 else ""
    year = parts[2] if len(parts) > 2 else ""
    photo_html = _photo_block(photo, layout) if photo else ""
    hero_html = f'<div class="hero">{photo_html}</div>' if photo else ""
    return f"""
    <div class="deco-top"></div>
    {hero_html}
    <div class="body">
      <div class="save-date-tag">{L["save_date"]}</div>
      <div class="ornament-row"><div class="line"></div><div class="dot"></div><div class="line"></div></div>
      <div class="monogram">{(mireasa[:1] + ' & ' + mire[:1]).upper() if mireasa and mire else '&'}</div>
      <div class="names-deco">{mireasa} <span class="amp">&</span> {mire}</div>
      <div class="ornament-row"><div class="line"></div><div class="dot"></div><div class="line"></div></div>
      {f'<div class="date-row"><div><div class="num">{day}</div><div class="lbl">{weekday or "&nbsp;"}</div></div><div class="date-sep"></div><div><div class="num">{month}</div><div class="lbl">{L["months"][int(month)-1] if month.isdigit() and 1<=int(month)<=12 else "&nbsp;"}</div></div><div class="date-sep"></div><div><div class="num">{year}</div><div class="lbl">&nbsp;</div></div></div>' if data_short else ''}
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>
    <div class="deco-bot"></div>"""


def _render_layout_luxe(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    photo_html = f'<div class="photo-luxe"><img src="{photo}" alt=""/></div>' if photo else f'<div class="photo-luxe-fallback">✦</div>'
    return f"""
    <div class="body">
      {photo_html}
      <div class="eyebrow">{L["save_date"]}</div>
      <div class="luxe-names">{mireasa}</div>
      <div class="luxe-and">— & —</div>
      <div class="luxe-names">{mire}</div>
      <div class="luxe-divider"></div>
      {f'<div class="luxe-date">{data_long}</div>' if data_long else ''}
      {f'<div class="luxe-weekday">{weekday}</div>' if weekday else ''}
      <div class="luxe-divider"></div>
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>"""


def _render_layout_magazine(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    parts = data_short.split(".") if data_short else ["","",""]
    day = parts[0] if len(parts) > 0 else ""
    month = parts[1] if len(parts) > 1 else ""
    year = parts[2] if len(parts) > 2 else ""
    photo_html = f'<img src="{photo}" alt=""/>' if photo else f'<div class="mag-hero-fallback">—</div>'
    return f"""
    <div class="mag-header">
      <div class="iss"><strong>VOL. 01</strong> · {L["title"].upper()}</div>
      <div class="iss">№ {year[-2:] if year else "—"}</div>
    </div>
    <div class="mag-hero">{photo_html}</div>
    <div class="mag-numbers">
      <div class="mag-num-cell"><div class="mag-num">{day or "—"}</div><div class="mag-lbl">{(weekday or '').upper()}</div></div>
      <div class="mag-num-cell"><div class="mag-num">{month or "—"}.{year[-2:] if year else "—"}</div><div class="mag-lbl">{L["months"][int(month)-1].upper() if month.isdigit() and 1<=int(month)<=12 else ''}</div></div>
    </div>
    <div class="body">
      <div class="mag-eyebrow">{L["save_date"]}</div>
      <div class="mag-names">{mireasa}<br/><span class="amp">&</span> {mire}</div>
      <div class="mag-rule"></div>
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>"""


def _render_layout_botanical(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    photo_html = f'<div class="photo-bot"><img src="{photo}" alt=""/></div>' if photo else f'<div class="photo-bot-fallback">✿</div>'
    return f"""
    <div style="color: {palette['accent']}">
      {_LEAF_SVG}
      {_LEAF_SVG_BR}
    </div>
    <div class="body">
      {photo_html}
      <div class="bot-eyebrow">{L["save_date"]}</div>
      <div class="bot-monogram">{(mireasa[:1] + '&' + mire[:1]) if mireasa and mire else '&'}</div>
      <div class="bot-names">{mireasa} <span class="amp">&</span> {mire}</div>
      <div class="bot-leaf-rule">
        <div class="line"></div>
        <span style="font-size:14px">✿</span>
        <div class="line"></div>
      </div>
      {('<div style="font-family: ' + chr(39) + 'Playfair Display' + chr(39) + ', serif; font-size: 18px; color: ' + palette['accent'] + '; letter-spacing: 2px;">' + data_long + '</div>') if data_long else ''}
      {('<div style="font-size: 11px; letter-spacing: 4px; color: ' + palette['muted'] + '; text-transform: uppercase; margin-top: 4px;">' + weekday + '</div>') if weekday else ''}
      <div class="bot-leaf-rule">
        <div class="line"></div>
        <span style="font-size:14px">✿</span>
        <div class="line"></div>
      </div>
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>"""


def _render_layout_vintage(mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L, family_html, locations_html, rsvp_html) -> str:
    photo_html = f'<div class="photo-vint"><img src="{photo}" alt=""/></div>' if photo else f'<div class="photo-vint-fallback">♥</div>'
    return f"""
    <div style="color: {palette['accent']}; text-align: center;">
      {_FLORAL_SVG}
    </div>
    <div class="body">
      <div class="vint-eyebrow">{L["intro_short"]}</div>
      {photo_html}
      <div class="vint-names">{mireasa} <span class="amp">&</span> {mire}</div>
      {f'<div class="vint-ribbon">{data_long}</div>' if data_long else ''}
      <p class="intro">{L["intro"]}</p>
      {family_html}
      {locations_html}
      {rsvp_html}
    </div>"""


def _render_invitation(code: str, invitat: dict, user: dict, setup: dict) -> str:
    # Couple names
    mireasa = setup.get("mireasa") or (user.get("display_name") or "").split("&")[0].strip() or "Mireasa"
    mire = setup.get("mire") or ""
    if not mire and "&" in (user.get("display_name") or ""):
        mire = (user.get("display_name") or "").split("&", 1)[1].strip()
    mire = mire or "Mirele"

    # Language — use bride/groom's profile language; fallback to ro
    lang = (user.get("language") or "ro").lower()
    if lang not in INV_I18N:
        lang = "ro"
    L = INV_I18N[lang]

    # Date
    data_long, data_short, weekday = _format_invitation_date(user.get("data_nunta") or "", lang)

    # Theme
    raw_theme = setup.get("theme") or "ivory_elegant"
    theme_key = _THEME_LEGACY.get(raw_theme, raw_theme)
    if theme_key not in THEME_DATA:
        theme_key = "ivory_elegant"
    palette = THEME_DATA[theme_key]
    layout = palette["layout"]

    # Common blocks
    photo = setup.get("couple_photo") or ""
    family_html = _build_family_block(setup, L)
    locations_html = _build_locations_block(setup.get("locations") or [], palette, L)
    guest_nume = invitat.get("nume", "")
    rsvp_html = _rsvp_block(code, guest_nume, invitat.get("confirmat") or "in_asteptare", L)

    # Render layout
    layout_renderers = {
        "classic": _render_layout_classic,
        "ornate": _render_layout_ornate,
        "luxe": _render_layout_luxe,
        "magazine": _render_layout_magazine,
        "botanical": _render_layout_botanical,
        "vintage": _render_layout_vintage,
    }
    inner_html = layout_renderers.get(layout, _render_layout_classic)(
        mireasa, mire, photo, data_long, data_short, weekday, palette, layout, L,
        family_html, locations_html, rsvp_html,
    )

    css = _theme_css(palette, layout)

    return f"""<!DOCTYPE html>
<html lang="{lang}">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
<title>{L['title']} — {mireasa} & {mire}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:ital,wght@0,400;0,600;1,400&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
<style>{css}</style>
</head>
<body>
  <div class="card">
    {inner_html}
  </div>
  <div class="footer">{L['footer']}</div>
<script>
async function rsvp(status) {{
  const btns = document.querySelectorAll('.btn-yes, .btn-no');
  btns.forEach(b => b.disabled = true);
  var sub = document.getElementById('submitting');
  if (sub) sub.style.display = 'block';
  try {{
    const r = await fetch('/api/invitation/{code}/rsvp', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ confirmat: status }})
    }});
    if (!r.ok) throw new Error('Eroare');
    location.reload();
  }} catch (e) {{
    alert({L["err"]!r});
    btns.forEach(b => b.disabled = false);
    if (sub) sub.style.display = 'none';
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
