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
from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, EmailStr


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
async def public_rsvp(code: str, body: RsvpIn):
    if body.confirmat not in ("confirmat", "refuzat"):
        raise HTTPException(status_code=400, detail="Status invalid")
    res = await db.invitati.update_one(
        {"id": code},
        {"$set": {"confirmat": body.confirmat, "responded_at": now_iso()}},
    )
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Invitație inexistentă")
    return {"ok": True, "confirmat": body.confirmat}


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
