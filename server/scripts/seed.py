"""Idempotent database seed script for OGK-Server.

Seeds:
1. >= 220 safe categorized domains across all 6 categories:
   - education, entertainment, social_media, games, inappropriate (100% neutral simulated domains ONLY),
     uncategorized.
   STRICTLY PROHIBITED from including any real adult/NSFW domains.
2. Demo accounts (Argon2id hashed):
   - Admin     : admin@ogk.local    / AdminPass123!
   - Parent    : parent@ogk.local   / ParentPass123!
   - Child-view: child@ogk.local    / ChildPass123!
   - Parent 2  : parent2@ogk.local  / Parent2Pass123!
3. Demo child profile ("Be An", ages 6-11) with default HMAC-SHA256 signed policy.

Usage:
    python -m server.scripts.seed
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from server.app.crypto import encrypt_field
from server.app.database import Base, SessionLocal, engine
from server.app.models import Child, DomainCategory, Policy, User
from server.app.security import hash_password
from server.app.services.policy_service import create_default_policy, sign_and_persist_policy

SEED_DOMAINS: dict[str, list[str]] = {
    "education": [
        "khanacademy.org", "wikipedia.org", "wiktionary.org", "wikibooks.org", "scratch.mit.edu",
        "code.org", "duolingo.com", "coursera.org", "edx.org", "wolframalpha.com",
        "nationalgeographic.com", "nasa.gov", "britannica.com", "ted.com", "geogebra.org",
        "desmos.com", "quizlet.com", "brilliant.org", "codecademy.com", "w3schools.com",
        "python.org", "mozilla.org", "mit.edu", "stanford.edu", "harvard.edu",
        "ox.ac.uk", "cam.ac.uk", "hcmus.edu.vn", "vnedu.vn", "olm.vn",
        "vio.edu.vn", "hocmai.vn", "loigiaihay.com", "vietjack.com", "tuyensinh247.com",
        "bbc.co.uk", "pbskids.org", "scholastic.com", "brainpop.com", "ixl.com",
        "mathisfun.com", "ck12.org", "openstax.org", "gutenberg.org", "archive.org",
        "smithsonianmag.com", "sciencedaily.com", "nature.com", "arxiv.org", "freecodecamp.org",
    ],
    "entertainment": [
        "youtube.com", "youtu.be", "netflix.com", "disneyplus.com", "spotify.com",
        "vimeo.com", "twitch.tv", "soundcloud.com", "crunchyroll.com", "imdb.com",
        "rottentomatoes.com", "nhaccuatui.com", "zingmp3.vn", "fptplay.vn", "vieon.vn",
        "dailymotion.com", "hulu.com", "primevideo.com", "apple.com", "music.apple.com",
        "bandcamp.com", "deezer.com", "pandora.com", "bilibili.com", "webtoons.com",
        "marvel.com", "dc.com", "pixar.com", "lego.com", "cartoonnetwork.com",
        "nick.com", "espn.com", "fifa.com", "nba.com", "olympics.com",
        "vtv.vn", "htv.com.vn", "kenh14.vn", "podcasts.google.com", "audible.com",
    ],
    "social_media": [
        "facebook.com", "fb.com", "instagram.com", "tiktok.com", "twitter.com",
        "x.com", "reddit.com", "snapchat.com", "pinterest.com", "linkedin.com",
        "discord.com", "telegram.org", "whatsapp.com", "zalo.me", "threads.net",
        "tumblr.com", "quora.com", "medium.com", "mastodon.social", "bsky.app",
        "wechat.com", "line.me", "viber.com", "skype.com", "messenger.com",
        "vk.com", "weibo.com", "flickr.com", "meetup.com", "nextdoor.com",
        "clubhouse.com", "bereal.com", "lemon8-app.com", "vkontakte.ru", "signal.org",
    ],
    "games": [
        "roblox.com", "minecraft.net", "steampowered.com", "steamcommunity.com", "epicgames.com",
        "chess.com", "lichess.org", "poki.com", "coolmathgames.com", "crazygames.com",
        "itch.io", "ea.com", "ubisoft.com", "riotgames.com", "leagueoflegends.com",
        "playvalorant.com", "nintendo.com", "playstation.com", "xbox.com", "garena.vn",
        "blizzard.com", "activision.com", "supercell.com", "hoyoverse.com", "genshin.hoyoverse.com",
        "miniclip.com", "kongregate.com", "armorgames.com", "newgrounds.com", "friv.com",
        "y8.com", "gamevui.vn", "trochoi.net", "ign.com", "gamespot.com",
        "pcgamer.com", "kotaku.com", "polygon.com", "nexusmods.com", "curseforge.com",
    ],
    # STRICTLY neutral simulated domains ONLY (zero real adult/NSFW domains)
    "inappropriate": [
        f"adult-sim-{i:02d}.test" for i in range(1, 16)
    ] + [
        f"blocked-test-{i:02d}.example" for i in range(1, 16)
    ] + [
        f"gambling-sim-{i:02d}.test" for i in range(1, 6)
    ],
    "uncategorized": [
        "example.com", "example.org", "example.net",
    ] + [
        f"neutral-site-{i:02d}.test" for i in range(1, 23)
    ],
}


def seed_database(db: Session) -> dict[str, int]:
    """Seed safe domains and demo accounts idempotently. Returns summary counts."""
    existing_domains = set(db.execute(select(DomainCategory.domain)).scalars().all())
    added_domains = 0
    for category, domains in SEED_DOMAINS.items():
        for dom in domains:
            dom_clean = dom.strip().lower()
            if dom_clean not in existing_domains:
                db.add(DomainCategory(domain=dom_clean, category=category, is_seed=True))
                existing_domains.add(dom_clean)
                added_domains += 1
    db.flush()

    def _get_or_create_user(
        email: str,
        display_name: str,
        password: str,
        role: str,
        parent_id: int | None = None,
    ) -> User:
        u = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
        if u is None:
            u = User(
                email=email,
                display_name=display_name,
                password_hash=hash_password(password),
                role=role,
                parent_id=parent_id,
            )
            db.add(u)
            db.flush()
        return u

    _get_or_create_user("admin@ogk.local", "OGK Admin", "AdminPass123!", "admin")
    parent1 = _get_or_create_user("parent@ogk.local", "Phu Huynh Minh", "ParentPass123!", "parent")
    child_user = _get_or_create_user(
        "child@ogk.local", "Be An", "ChildPass123!", "child-view", parent_id=parent1.id
    )
    _get_or_create_user("parent2@ogk.local", "Phu Huynh Lan", "Parent2Pass123!", "parent")

    child = db.execute(select(Child).where(Child.parent_id == parent1.id)).scalar_one_or_none()
    if child is None:
        child = Child(
            parent_id=parent1.id,
            child_user_id=child_user.id,
            name_encrypted=encrypt_field("Be An"),
            age_group="6-11",
            timezone="Asia/Ho_Chi_Minh",
        )
        db.add(child)
        db.flush()
        create_default_policy(db, child_id=child.id, parent_id=parent1.id)
    else:
        policy = db.execute(select(Policy).where(Policy.child_id == child.id)).scalar_one_or_none()
        if policy is not None:
            sign_and_persist_policy(policy, db)

    db.commit()
    total_domains = len(existing_domains)
    return {"added_domains": added_domains, "total_domains": total_domains}


def main() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        result = seed_database(db)
    print(
        f"[OGK] Seed completed: {result['total_domains']} safe categorized domains "
        f"(+{result['added_domains']} newly inserted)."
    )
    print("[OGK] Demo credentials:")
    print("  Admin     : admin@ogk.local   / AdminPass123!")
    print("  Parent    : parent@ogk.local  / ParentPass123!")
    print("  Child-view: child@ogk.local   / ChildPass123!")
    print("  Parent 2  : parent2@ogk.local / Parent2Pass123!")


if __name__ == "__main__":
    main()
