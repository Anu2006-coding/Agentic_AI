from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session
import sqlite3
import os
import re
import secrets
from datetime import date, datetime, timedelta
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

DB_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "phishguard.db"
)


# =====================================
# DATABASE INITIALIZATION
# =====================================

def init_db():

    with sqlite3.connect(DB_PATH) as conn:

        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
        """)

        conn.execute("""
            CREATE TABLE IF NOT EXISTS scans (

                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER REFERENCES users(id),
                created_at TEXT NOT NULL,
                sender TEXT,
                subject TEXT,
                verdict TEXT NOT NULL,
                score INTEGER NOT NULL,
                findings TEXT NOT NULL,
                recommendations TEXT NOT NULL

            )
        """)

        scan_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(scans)")
        }
        if "user_id" not in scan_columns:
            conn.execute(
                "ALTER TABLE scans ADD COLUMN user_id INTEGER REFERENCES users(id)"
            )

        conn.execute(
            "CREATE INDEX IF NOT EXISTS scans_user_id_idx ON scans(user_id)"
        )


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            with sqlite3.connect(DB_PATH) as conn:
                has_users = conn.execute(
                    "SELECT EXISTS(SELECT 1 FROM users)"
                ).fetchone()[0]
            return redirect(url_for("login" if has_users else "register"))
        return view(*args, **kwargs)
    return wrapped_view

init_db()


# =====================================
# EMAIL URL EXTRACTION
# =====================================

def extract_urls(text):

    pattern = r"""https?://[^\s<>"']+|www\.[^\s<>"']+"""

    urls = re.findall(pattern, text or "", re.I)

    return list(dict.fromkeys(
        url.rstrip(".,);]") for url in urls
    ))


# =====================================
# PHISHING DETECTION ENGINE
# =====================================

def analyze_email(sender, subject, body, attachments=None):

    sender = sender or ""
    subject = subject or ""
    body = body or ""

    full_text = (subject + " " + body).lower()

    score = 0
    findings = []

    urgent_words = [
        "urgent",
        "immediately",
        "account suspended",
        "account will be blocked",
        "act now",
        "final warning",
        "verify now",
        "within 24 hours"
    ]

    credential_words = [
        "password",
        "login",
        "sign in",
        "verify your account",
        "confirm your identity",
        "otp",
        "credentials"
    ]

    payment_words = [
        "gift card",
        "wire transfer",
        "payment overdue",
        "bank details"
    ]

    # Check urgency

    urgent_hits = [
        word for word in urgent_words
        if word in full_text
    ]

    if urgent_hits:

        score += min(20, 5 + 3 * len(urgent_hits))

        findings.append(
            "Urgent language detected: " +
            ", ".join(urgent_hits)
        )

    # Check credential requests

    credential_hits = [
        word for word in credential_words
        if word in full_text
    ]

    if credential_hits:

        score += min(25, 8 + 4 * len(credential_hits))

        findings.append(
            "Credential-related wording detected: " +
            ", ".join(credential_hits)
        )

    # Check financial requests

    payment_hits = [
        word for word in payment_words
        if word in full_text
    ]

    if payment_hits:

        score += min(15, 5 + 3 * len(payment_hits))

        findings.append(
            "Financial request wording detected: " +
            ", ".join(payment_hits)
        )

    # Extract and inspect URLs

    urls = extract_urls(body)

    shorteners = [
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl"
    ]

    risky_extensions = [
        ".zip",
        ".xyz",
        ".top",
        ".click",
        ".work"
    ]

    if urls:

        findings.append(
            str(len(urls)) + " URL(s) detected in email."
        )

    for url in urls:

        candidate = url

        if not candidate.lower().startswith(
            ("http://", "https://")
        ):
            candidate = "http://" + candidate

        parsed = urlparse(candidate)

        domain = (parsed.hostname or "").lower()

        if domain in shorteners:

            score += 15

            findings.append(
                "URL shortener detected: " + domain
            )

        if re.fullmatch(
            r"\d{1,3}(?:\.\d{1,3}){3}",
            domain
        ):

            score += 20

            findings.append(
                "IP address used instead of a domain: " + domain
            )

        if any(domain.endswith(ext) for ext in risky_extensions):

            score += 10

            findings.append(
                "Unusual URL extension detected: " + domain
            )

        if parsed.scheme == "http":

            score += 5

            findings.append(
                "Non-encrypted HTTP link detected: " + domain
            )

    # Check sender

    if sender and "@" not in sender:

        score += 10

        findings.append(
            "Sender address format appears invalid."
        )

    elif sender and "@" in sender:

        domain = sender.rsplit("@", 1)[-1].strip(" >").lower()

        brand_words = [
            "bank",
            "payroll",
            "microsoft",
            "administrator",
            "it support"
        ]

        if domain in [
            "gmail.com",
            "yahoo.com",
            "outlook.com",
            "hotmail.com"
        ] and any(word in full_text for word in brand_words):

            score += 12

            findings.append(
                "Free email provider appears to be used "
                "for an organizational claim."
            )

    # Check attachment names

    dangerous_extensions = [
        ".exe",
        ".scr",
        ".js",
        ".vbs",
        ".bat",
        ".cmd",
        ".ps1",
        ".hta",
        ".iso",
        ".jar"
    ]

    for filename in (attachments or []):

        extension = os.path.splitext(
            filename.lower()
        )[1]

        if extension in dangerous_extensions:

            score += 20

            findings.append(
                "Potentially dangerous attachment: " + filename
            )

    # Final score

    score = min(score, 100)

    if not findings:

        findings.append(
            "No obvious phishing indicators detected "
            "by the current rule-based checks."
        )

    # Threat classification

    if score >= 60:

        verdict = "High risk"

        recommendations = [
            "Do not click suspicious links.",
            "Do not open unexpected attachments.",
            "Never share passwords or OTPs.",
            "Report the email to the security team."
        ]

    elif score >= 30:

        verdict = "Suspicious"

        recommendations = [
            "Verify the sender independently.",
            "Avoid clicking links in the email.",
            "Ask the security team to review the message."
        ]

    else:

        verdict = "Low indicators detected"

        recommendations = [
            "No strong indicators were detected by this analysis.",
            "Verify unexpected requests independently.",
            "Check links and sender details before interacting."
        ]

    return {
        "score": score,
        "verdict": verdict,
        "findings": findings,
        "recommendations": recommendations,
        "urls": urls
    }


# =====================================
# EML FILE EXTRACTION
# =====================================

def parse_eml(file):

    message = BytesParser(
        policy=policy.default
    ).parsebytes(file.read())

    sender = str(message.get("From", ""))

    subject = str(message.get("Subject", ""))

    body_parts = []
    attachments = []

    if message.is_multipart():

        for part in message.walk():

            filename = part.get_filename()

            if filename:

                attachments.append(filename)

            elif part.get_content_type() == "text/plain":

                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

    else:

        try:
            body_parts.append(message.get_content())
        except Exception:
            pass

    return (
        sender,
        subject,
        "\n".join(str(part) for part in body_parts),
        attachments
    )


# =====================================
# DASHBOARD ROUTE
# =====================================

@app.route("/")
@login_required
def index():

    with sqlite3.connect(DB_PATH) as conn:

        scans = conn.execute("""
            SELECT id, created_at, sender,
                   subject, verdict, score
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 8
        """, (session["user_id"],)).fetchall()

        total = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ?",
            (session["user_id"],)
        ).fetchone()[0]

        high = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE user_id = ? AND verdict = ?",
            (session["user_id"], "High risk")
        ).fetchone()[0]

    return render_template(
        "index.html",
        scans=scans,
        total=total,
        high=high
    )


@app.route("/new-investigation")
@login_required
def new_investigation():
    return render_template("investigation.html")


@app.route("/analytics")
@login_required
def analytics():
    user_id = session["user_id"]
    today = date.today()
    dates = [today - timedelta(days=offset) for offset in range(6, -1, -1)]

    with sqlite3.connect(DB_PATH) as conn:
        totals = conn.execute("""
            SELECT COUNT(*),
                   COALESCE(ROUND(AVG(score)), 0),
                   COALESCE(SUM(CASE WHEN score >= 60 THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN score >= 30 AND score < 60 THEN 1 ELSE 0 END), 0),
                   COALESCE(SUM(CASE WHEN score < 30 THEN 1 ELSE 0 END), 0)
            FROM scans
            WHERE user_id = ?
        """, (user_id,)).fetchone()

        daily_rows = conn.execute("""
            SELECT substr(created_at, 1, 10), COUNT(*), ROUND(AVG(score))
            FROM scans
            WHERE user_id = ? AND substr(created_at, 1, 10) >= ?
            GROUP BY substr(created_at, 1, 10)
        """, (user_id, dates[0].isoformat())).fetchall()

        recent_scans = conn.execute("""
            SELECT id, created_at, sender, subject, verdict, score
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
            LIMIT 10
        """, (user_id,)).fetchall()

    daily_by_date = {
        row[0]: {"count": row[1], "average_score": row[2]}
        for row in daily_rows
    }
    daily_max = max(
        (daily_by_date.get(day.isoformat(), {}).get("count", 0) for day in dates),
        default=0
    )
    daily_activity = [
        {
            "label": day.strftime("%b %d"),
            "count": daily_by_date.get(day.isoformat(), {}).get("count", 0),
            "width": round(
                100 * daily_by_date.get(day.isoformat(), {}).get("count", 0)
                / daily_max
            ) if daily_max else 0
        }
        for day in dates
    ]

    risk_bands = [
        {"label": "High risk", "count": totals[2], "style": "high"},
        {"label": "Suspicious", "count": totals[3], "style": "suspicious"},
        {"label": "Low indicators", "count": totals[4], "style": "low"}
    ]

    return render_template(
        "analytics.html",
        total=totals[0],
        average_score=totals[1],
        high_count=totals[2],
        risk_bands=risk_bands,
        daily_activity=daily_activity,
        recent_scans=recent_scans
    )


def build_assistant_answer(scan, question):
    normalized_question = question.lower()
    findings = [item for item in scan[6].splitlines() if item]
    recommendations = [item for item in scan[7].splitlines() if item]
    score = scan[5]

    if score >= 60:
        risk_level = "high risk"
        risk_explanation = "The score is in the high-risk range (60–100)."
    elif score >= 30:
        risk_level = "suspicious"
        risk_explanation = "The score is in the suspicious range (30–59)."
    else:
        risk_level = "low indicators detected"
        risk_explanation = "The score is in the low-indicator range (0–29)."

    if any(word in normalized_question for word in ("score", "risk", "verdict", "mean")):
        title = "Understanding this risk score"
        explanation = (
            f"Investigation #{scan[0]} was classified as {scan[4]} with a "
            f"score of {score}/100. {risk_explanation} This is a rule-based "
            "indicator, not a probability that the email is malicious."
        )
        details = findings[:4]
    elif any(word in normalized_question for word in ("link", "url", "website", "click")):
        title = "About links in this email"
        url_finding = next(
            (item for item in findings if "url(s) detected" in item.lower()),
            None
        )
        details = [url_finding] if url_finding else [
            "The saved findings do not report any URLs in this message."
        ]
        explanation = (
            "The scan summary can report whether links were detected, but "
            "MailSentinel does not save the original link destinations in scan history. "
            "Avoid clicking unexpected links; visit the sender's official website "
            "directly if you need to verify a request."
        )
    elif any(word in normalized_question for word in ("attach", "file", "document")):
        attachment_findings = [
            item for item in findings
            if "attachment" in item.lower()
        ]
        title = "About email attachments"
        explanation = (
            "The saved findings only identify attachment risks that matched "
            "MailSentinel's checks. A clean result does not guarantee that a file is safe."
        )
        details = attachment_findings or [
            "No potentially dangerous attachment was recorded in this scan's findings."
        ]
    elif any(word in normalized_question for word in ("why", "finding", "suspicious", "detected")):
        title = "Why the scan flagged this email"
        explanation = (
            f"The scan classified this message as {scan[4]} ({score}/100) "
            "based on the indicators listed below."
        )
        details = findings[:6]
    else:
        title = f"Investigation #{scan[0]} summary"
        explanation = (
            f"This email was classified as {scan[4]} with a risk score of "
            f"{score}/100, which is {risk_level}. Here are the recorded indicators "
            "and suggested next steps."
        )
        details = findings[:5]

    return {
        "title": title,
        "explanation": explanation,
        "details": details,
        "recommendations": recommendations[:4],
        "scan_id": scan[0]
    }


@app.route("/assistant", methods=["GET", "POST"])
@login_required
def assistant():
    user_id = session["user_id"]
    with sqlite3.connect(DB_PATH) as conn:
        scans = conn.execute("""
            SELECT id, created_at, sender, subject, verdict, score
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
        """, (user_id,)).fetchall()

    selected_id = scans[0][0] if scans else None
    answer = None

    if request.method == "POST":
        question = request.form.get("question", "").strip()
        raw_scan_id = request.form.get("scan_id", "").strip()

        try:
            selected_id = int(raw_scan_id)
        except ValueError:
            selected_id = None

        selected_scan = None
        if selected_id is not None:
            with sqlite3.connect(DB_PATH) as conn:
                selected_scan = conn.execute("""
                    SELECT id, created_at, sender, subject, verdict, score,
                           findings, recommendations
                    FROM scans
                    WHERE id = ? AND user_id = ?
                """, (selected_id, user_id)).fetchone()

        if not question:
            flash("Enter a question about a scan.", "error")
        elif len(question) > 500:
            flash("Keep your question under 500 characters.", "error")
        elif selected_scan is None:
            flash("Choose one of your saved investigations first.", "error")
        else:
            answer = build_assistant_answer(selected_scan, question)

    return render_template(
        "assistant.html",
        scans=scans,
        selected_id=selected_id,
        question=request.form.get("question", "") if request.method == "POST" else "",
        answer=answer
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        confirm_password = request.form.get("confirm_password", "")

        if not name or not email or not password or not confirm_password:
            flash("Please complete every field.", "error")
        elif not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
            flash("Enter a valid email address.", "error")
        elif len(password) < 8:
            flash("Your password must be at least 8 characters long.", "error")
        elif password != confirm_password:
            flash("The passwords do not match.", "error")
        else:
            try:
                with sqlite3.connect(DB_PATH) as conn:
                    cursor = conn.execute("""
                        INSERT INTO users (name, email, password_hash, created_at)
                        VALUES (?, ?, ?, ?)
                    """, (
                        name,
                        email,
                        generate_password_hash(password),
                        datetime.now().strftime("%Y-%m-%d %H:%M")
                    ))
                    user_id = cursor.lastrowid
                    conn.execute(
                        "UPDATE scans SET user_id = ? WHERE user_id IS NULL",
                        (user_id,)
                    )
            except sqlite3.IntegrityError:
                flash("An account with that email already exists.", "error")
            else:
                flash("Your account is ready. Please log in.", "success")
                return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        with sqlite3.connect(DB_PATH) as conn:
            user = conn.execute("""
                SELECT id, name, password_hash
                FROM users
                WHERE email = ? COLLATE NOCASE
            """, (email,)).fetchone()

        if user is None or not check_password_hash(user[2], password):
            flash("Invalid email or password.", "error")
        else:
            session.clear()
            session["user_id"] = user[0]
            session["user_name"] = user[1]
            return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    flash("You have been logged out.", "success")
    return redirect(url_for("login"))


# =====================================
# EMAIL ANALYSIS ROUTE
# =====================================

@app.route("/analyze", methods=["POST"])
@login_required
def analyze():

    sender = request.form.get("sender", "").strip()

    subject = request.form.get("subject", "").strip()

    body = request.form.get("body", "").strip()

    attachments = []

    upload = request.files.get("eml_file")

    if upload and upload.filename:

        if not upload.filename.lower().endswith(".eml"):

            flash("Please upload a valid .eml file.", "error")

            return redirect(url_for("new_investigation"))

        try:

            sender, subject, body, attachments = parse_eml(upload)

        except Exception:

            flash("Unable to read the uploaded email file.", "error")

            return redirect(url_for("new_investigation"))

    if not (sender or subject or body):

        flash("Please enter email information.", "error")

        return redirect(url_for("new_investigation"))

    result = analyze_email(
        sender,
        subject,
        body,
        attachments
    )

    findings_text = "\n".join(result["findings"])

    recommendations_text = "\n".join(
        result["recommendations"]
    )

    with sqlite3.connect(DB_PATH) as conn:

        cursor = conn.execute("""
            INSERT INTO scans
            (user_id, created_at, sender, subject, verdict,
             score, findings, recommendations)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            session["user_id"],
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            sender,
            subject,
            result["verdict"],
            result["score"],
            findings_text,
            recommendations_text
        ))

        scan_id = cursor.lastrowid

    return render_template(
        "report.html",
        result=result,
        sender=sender,
        subject=subject,
        scan_id=scan_id
    )


# =====================================
# INVESTIGATION HISTORY
# =====================================

@app.route("/history")
@login_required
def history():

    with sqlite3.connect(DB_PATH) as conn:

        scans = conn.execute("""
            SELECT id, created_at, sender,
                   subject, verdict, score
            FROM scans
            WHERE user_id = ?
            ORDER BY id DESC
        """, (session["user_id"],)).fetchall()

    return render_template(
        "history.html",
        scans=scans
    )


# =====================================
# INDIVIDUAL REPORT
# =====================================

@app.route("/scan/<int:scan_id>")
@login_required
def scan_detail(scan_id):

    with sqlite3.connect(DB_PATH) as conn:

        scan = conn.execute("""
            SELECT id, created_at, sender,
                   subject, verdict, score,
                   findings, recommendations
            FROM scans
            WHERE id = ? AND user_id = ?
        """, (scan_id, session["user_id"])).fetchone()

    if scan is None:

        flash("Investigation not found.")

        return redirect(url_for("history"))

    return render_template(
        "detail.html",
        scan=scan
    )


# =====================================
# START APPLICATION
# =====================================

if __name__ == "__main__":
    app.run(
        debug=True,
        host="127.0.0.1",
        port=5000
    )