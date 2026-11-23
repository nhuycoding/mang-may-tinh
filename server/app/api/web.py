"""Web UI routes serving the Parent Dashboard and Child Transparency Screen (Jinja2 + HTMX)."""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Depends, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import select
from sqlalchemy.orm import Session

from server.app.api.reports import get_child_report_summary, get_today_child_transparency
from server.app.crypto import decrypt_field, hash_token
from server.app.database import get_db
from server.app.i18n import load_translations, resolve_language
from server.app.models import AuditLog, Child, Device, Policy, TimeExtensionRequest, User, WebSession, utcnow
from server.app.security import SESSION_COOKIE_NAME, _as_utc
from server.app.services.policy_service import build_policy_payload, create_default_policy

DASHBOARD_DIR = Path(__file__).resolve().parents[3] / "dashboard"
templates = Jinja2Templates(directory=str(DASHBOARD_DIR / "templates"))

router = APIRouter(tags=["web"])


def _resolve_optional_session(
    ogk_session: str | None,
    db: Session,
) -> tuple[User, WebSession] | None:
    if not ogk_session:
        return None
    ws = db.get(WebSession, hash_token(ogk_session))
    now = utcnow()
    if ws is None or ws.revoked_at is not None:
        return None
    exp = _as_utc(ws.expires_at)
    if exp is not None and exp <= now:
        return None
    user = db.get(User, ws.user_id)
    if user is None or not user.is_active:
        return None
    return user, ws


@router.get("/", response_class=HTMLResponse)
def root_redirect(
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    sess = _resolve_optional_session(ogk_session, db)
    if sess is None:
        return RedirectResponse(url="/login", status_code=302)
    user, _ws = sess
    target = "/child" if user.role == "child-view" else "/dashboard"
    return RedirectResponse(url=target, status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(
    request: Request,
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    sess = _resolve_optional_session(ogk_session, db)
    if sess is not None:
        user, _ws = sess
        return RedirectResponse(url="/child" if user.role == "child-view" else "/dashboard", status_code=302)
    lang = resolve_language(request)
    return templates.TemplateResponse(
        request,
        "login.html",
        {"user": None, "csrf_token": "", "lang": lang, "t": load_translations(lang)},
    )


@router.get("/dashboard", response_class=HTMLResponse)
def parent_dashboard_page(
    request: Request,
    child_id: int | None = Query(default=None),
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    sess = _resolve_optional_session(ogk_session, db)
    if sess is None:
        return RedirectResponse(url="/login", status_code=302)
    user, ws = sess
    if user.role == "child-view":
        return RedirectResponse(url="/child", status_code=302)

    stmt = select(Child).order_by(Child.id.asc())
    if user.role == "parent":
        stmt = stmt.where(Child.parent_id == user.id)
    raw_children = db.execute(stmt).scalars().all()

    children_view = [
        {"id": c.id, "name": decrypt_field(c.name_encrypted), "age_group": c.age_group}
        for c in raw_children
    ]

    selected_child_obj = None
    if raw_children:
        if child_id is not None:
            selected_child_obj = next((c for c in raw_children if c.id == child_id), raw_children[0])
        else:
            selected_child_obj = raw_children[0]

    lang = resolve_language(request)
    context: dict = {
        "user": user,
        "csrf_token": ws.csrf_token,
        "lang": lang,
        "t": load_translations(lang),
        "children": children_view,
        "selected_child": None,
        "summary": None,
        "devices": [],
        "policy": None,
        "policy_payload": None,
        "extensions": [],
        "audit_logs": [],
    }

    if selected_child_obj is not None:
        context["selected_child"] = {
            "id": selected_child_obj.id,
            "name": decrypt_field(selected_child_obj.name_encrypted),
            "age_group": selected_child_obj.age_group,
        }
        policy = db.execute(
            select(Policy).where(Policy.child_id == selected_child_obj.id)
        ).scalar_one_or_none()
        if policy is None:
            policy = create_default_policy(
                db, child_id=selected_child_obj.id, parent_id=selected_child_obj.parent_id
            )
            db.commit()
            db.refresh(policy)

        context["policy"] = policy
        context["policy_payload"] = build_policy_payload(policy, db=db)
        context["summary"] = get_child_report_summary(selected_child_obj.id, days=7, user=user, db=db)
        context["devices"] = (
            db.execute(
                select(Device)
                .where(Device.child_id == selected_child_obj.id)
                .order_by(Device.created_at.desc())
            )
            .scalars()
            .all()
        )
        context["extensions"] = (
            db.execute(
                select(TimeExtensionRequest)
                .where(TimeExtensionRequest.child_id == selected_child_obj.id)
                .order_by(TimeExtensionRequest.created_at.desc())
                .limit(20)
            )
            .scalars()
            .all()
        )
        audit_stmt = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(30)
        if user.role == "parent":
            audit_stmt = audit_stmt.where(AuditLog.parent_id == user.id)
        context["audit_logs"] = db.execute(audit_stmt).scalars().all()

    return templates.TemplateResponse(request, "parent_dashboard.html", context)


@router.get("/dashboard/partials/extensions", response_class=HTMLResponse)
def extensions_partial(
    request: Request,
    child_id: int = Query(...),
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    sess = _resolve_optional_session(ogk_session, db)
    if sess is None:
        return HTMLResponse("", status_code=401)
    user, _ws = sess

    stmt = select(Child).where(Child.id == child_id)
    if user.role == "parent":
        stmt = stmt.where(Child.parent_id == user.id)
    child = db.execute(stmt).scalar_one_or_none()
    if child is None:
        return HTMLResponse("", status_code=404)

    extensions = (
        db.execute(
            select(TimeExtensionRequest)
            .where(TimeExtensionRequest.child_id == child.id)
            .order_by(TimeExtensionRequest.created_at.desc())
            .limit(20)
        )
        .scalars()
        .all()
    )
    lang = resolve_language(request)
    return templates.TemplateResponse(
        request,
        "partials/extensions.html",
        {"extensions": extensions, "lang": lang, "t": load_translations(lang)},
    )


@router.get("/child", response_class=HTMLResponse)
def child_transparency_page(
    request: Request,
    child_id: int | None = Query(default=None),
    ogk_session: str | None = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    db: Session = Depends(get_db),
):
    """Child Transparency Screen: 'What I used today' + read-only Audit Log of parent changes."""
    sess = _resolve_optional_session(ogk_session, db)
    if sess is None:
        return RedirectResponse(url="/login", status_code=302)
    user, ws = sess

    if user.role == "child-view":
        child = db.execute(select(Child).where(Child.child_user_id == user.id)).scalar_one_or_none()
    else:
        stmt = select(Child).order_by(Child.id.asc())
        if user.role == "parent":
            stmt = stmt.where(Child.parent_id == user.id)
        if child_id is not None:
            stmt = stmt.where(Child.id == child_id)
        child = db.execute(stmt).scalars().first()

    if child is None:
        return RedirectResponse(url="/dashboard", status_code=302)

    today = get_today_child_transparency(child.id, user=user, db=db)
    audit_logs = (
        db.execute(
            select(AuditLog)
            .where(AuditLog.parent_id == child.parent_id)
            .order_by(AuditLog.timestamp.desc())
            .limit(30)
        )
        .scalars()
        .all()
    )
    lang = resolve_language(request)
    return templates.TemplateResponse(
        request,
        "child_transparency.html",
        {
            "user": user,
            "csrf_token": ws.csrf_token,
            "lang": lang,
            "t": load_translations(lang),
            "child_name": decrypt_field(child.name_encrypted),
            "today": today,
            "audit_logs": audit_logs,
        },
    )
