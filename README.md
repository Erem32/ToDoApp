This is a minimal FastAPI-powered to-do list web app that demonstrates:

* **User accounts**: register, log in/out, secure password hashing
* **Task CRUD**: add new items, view your list, delete completed tasks
* **Persistence**: SQLite database via SQLAlchemy ORM
* **Server-rendered UI**: Jinja2 templates + plain HTML/CSS for a lightweight frontend
* **Cookie-based auth**: FastAPI-Login manages session cookies

Clone the repo, install dependencies (`pip install -r requirements.txt`), copy `.env.example` to `.env`, then start with:

```bash
uvicorn app.main:app --reload
```

Browse to [http://localhost:8000](http://localhost:8000) to register and start managing your tasks.
