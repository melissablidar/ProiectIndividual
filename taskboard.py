import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import sqlite3
import datetime
import csv
import json
import os
import re

DB_PATH = "taskboard.db"
DRAFT_PATH = "taskboard_draft.json"

STATUSES = ["todo", "doing", "done"]
STATUS_LABEL = {"todo": "To Do", "doing": "Doing", "done": "Done"}
PRIORITIES = ["low", "medium", "high"]


# --------------------------------------
class TaskDB:
    def __init__(self, path=DB_PATH):
        self.conn = sqlite3.connect(path)
        self.conn.execute("PRAGMA foreign_keys = ON;")
        self._ensure()

    def _ensure(self):
        
        self.conn.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                description TEXT,
                status TEXT NOT NULL,
                priority TEXT NOT NULL,
                due_date TEXT,
                pinned INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        self.conn.commit()

        # Migration: add pinned if DB was created earlier without it
        cols = [row[1] for row in self.conn.execute("PRAGMA table_info(tasks)").fetchall()]
        if "pinned" not in cols:
            self.conn.execute("ALTER TABLE tasks ADD COLUMN pinned INTEGER NOT NULL DEFAULT 0;")
            self.conn.commit()

    def add_task(self, title, description, status, priority, due_date, pinned=0):
        now = datetime.datetime.utcnow().isoformat()
        self.conn.execute("""
            INSERT INTO tasks (title, description, status, priority, due_date, pinned, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (title, description, status, priority, due_date, int(bool(pinned)), now, now))
        self.conn.commit()

    def update_task(self, task_id, title, description, status, priority, due_date, pinned=0):
        now = datetime.datetime.utcnow().isoformat()
        self.conn.execute("""
            UPDATE tasks
            SET title=?, description=?, status=?, priority=?, due_date=?, pinned=?, updated_at=?
            WHERE id=?
        """, (title, description, status, priority, due_date, int(bool(pinned)), now, task_id))
        self.conn.commit()

    def delete_task(self, task_id):
        self.conn.execute("DELETE FROM tasks WHERE id=?", (task_id,))
        self.conn.commit()

    def get_task(self, task_id):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT id, title, description, status, priority, due_date, pinned, created_at, updated_at
            FROM tasks WHERE id=?
        """, (task_id,))
        return cur.fetchone()

    def list_tasks(self, search=None, status=None, priority=None, pinned_only=False, sort="updated_at"):
        q = """
            SELECT id, title, description, status, priority, due_date, pinned, created_at, updated_at
            FROM tasks
        """
        where = []
        params = []

        if search:
            where.append("(title LIKE ? OR description LIKE ?)")
            s = f"%{search}%"
            params.extend([s, s])

        if status and status != "all":
            where.append("status = ?")
            params.append(status)

        if priority and priority != "all":
            where.append("priority = ?")
            params.append(priority)

        if pinned_only:
            where.append("pinned = 1")

        if where:
            q += " WHERE " + " AND ".join(where)

        # Sorting
        if sort == "deadline":
            q += " ORDER BY (due_date IS NULL), due_date ASC"
        elif sort == "title":
            q += " ORDER BY lower(title) COLLATE NOCASE"
        elif sort == "created":
            q += " ORDER BY created_at DESC"
        else:
            q += " ORDER BY updated_at DESC"

        cur = self.conn.cursor()
        cur.execute(q, params)
        return cur.fetchall()

    def close(self):
        self.conn.close()


# -------------------- UI APP --------------------
class TaskBoardApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("TaskBoard")
        self.geometry("1180x680")
        self.minsize(980, 560)

        self.db = TaskDB()
        self.selected_task_id = None
        self.selected_status = None

        self._setup_style()
        self._build_ui()

        # Autosave draft (every 2s)
        self._draft_dirty = False
        self._load_draft_if_any()
        self.after(2000, self._autosave_tick)

        self.refresh()

        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def _setup_style(self):
        style = ttk.Style(self)
        style.theme_use("clam")
        style.configure(".", font=("Century Gothic", 10))
        style.configure("TFrame", background="#fdcbe1")
        style.configure("TFrame", background="#f8eaf0")
        style.configure("TLabelframe", background="#f8eaf0")
        style.configure("TLabelframe.Label", font=("Century Gothic", 10, "bold"))
        style.configure("TLabel", background="#fdcbe1")
        # Optional: colored ttk buttons via styles (works best on clam)
        style.configure("Primary.TButton", background="#2e86de", foreground="white")
        style.map("Primary.TButton", background=[("active", "#1b4f72")])

        style.configure("Success.TButton", background="#7ec79c", foreground="white")
        style.map("Success.TButton", background=[("active", "#1e8449")])

        style.configure("Danger.TButton", background="#f7877a", foreground="white")
        style.map("Danger.TButton", background=[("active", "#c0392b")])

        style.configure("Warning.TButton", background="#a5e2f1", foreground="black")
        style.map("Warning.TButton", background=[("active", "#0da5d4")])

    def _build_ui(self):
        # Top bar
        top = ttk.Frame(self, padding=10)
        top.pack(side=tk.TOP, fill=tk.X)

        ttk.Label(top, text="TaskBoard (Mini Trello)", style="Header.TLabel").grid(row=0, column=0, sticky="w")

        # Dashboard
        dash = ttk.Frame(top)
        dash.grid(row=0, column=1, sticky="e", padx=(20, 0))
        self.dash_var = tk.StringVar(value="Total: 0 | To Do: 0 | Doing: 0 | Done: 0 | Done%: 0%")
        ttk.Label(dash, textvariable=self.dash_var, style="Subtle.TLabel").pack(anchor="e")

        top.columnconfigure(0, weight=1)
        top.columnconfigure(1, weight=0)

        # Controls row
        controls = ttk.Frame(self, padding=(10, 0, 10, 10))
        controls.pack(side=tk.TOP, fill=tk.X)

        # Quick Add
        ttk.Label(controls, text="Quick Add:").pack(side=tk.LEFT)
        self.quick_var = tk.StringVar()
        quick_entry = ttk.Entry(controls, textvariable=self.quick_var, width=42)
        quick_entry.pack(side=tk.LEFT, padx=(6, 8))
        quick_entry.bind("<Return>", lambda e: self.quick_add())

        ttk.Button(controls, text="Add", style="Success.TButton", command=self.quick_add).pack(side=tk.LEFT)

        ttk.Label(controls, text="   Search:").pack(side=tk.LEFT, padx=(18, 4))
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(controls, textvariable=self.search_var, width=28)
        search_entry.pack(side=tk.LEFT)
        # LIVE SEARCH
        search_entry.bind("<KeyRelease>", lambda e: self.refresh())

        ttk.Button(controls, text="Clear", command=self.clear_search).pack(side=tk.LEFT, padx=8)

        # Filters
        self.filter_status = tk.StringVar(value="all")
        self.filter_priority = tk.StringVar(value="all")
        self.sort_var = tk.StringVar(value="updated")
        self.pinned_only_var = tk.BooleanVar(value=False)

        ttk.Label(controls, text="Status:").pack(side=tk.LEFT, padx=(10, 4))
        cb_status = ttk.Combobox(controls, textvariable=self.filter_status, state="readonly",
                                 values=["all"] + STATUSES, width=10)
        cb_status.pack(side=tk.LEFT)
        cb_status.bind("<<ComboboxSelected>>", lambda e: self.refresh())

        ttk.Label(controls, text="Priority:").pack(side=tk.LEFT, padx=(10, 4))
        cb_pr = ttk.Combobox(controls, textvariable=self.filter_priority, state="readonly",
                             values=["all"] + PRIORITIES, width=10)
        cb_pr.pack(side=tk.LEFT)
        cb_pr.bind("<<ComboboxSelected>>", lambda e: self.refresh())

        ttk.Label(controls, text="Sort:").pack(side=tk.LEFT, padx=(10, 4))
        cb_sort = ttk.Combobox(controls, textvariable=self.sort_var, state="readonly",
                               values=["updated", "created", "deadline", "title"], width=10)
        cb_sort.pack(side=tk.LEFT)
        cb_sort.bind("<<ComboboxSelected>>", lambda e: self.refresh())

        ttk.Checkbutton(controls, text="Pinned only ⭐", variable=self.pinned_only_var,
                        command=self.refresh).pack(side=tk.LEFT, padx=(12, 0))

        ttk.Button(controls, text="Export CSV", command=self.export_csv).pack(side=tk.RIGHT)

        # Main area
        main = ttk.Frame(self, padding=(10, 0, 10, 10))
        main.pack(fill=tk.BOTH, expand=True)

        main.columnconfigure(0, weight=2)
        main.columnconfigure(1, weight=2)
        main.columnconfigure(2, weight=2)
        main.columnconfigure(3, weight=3)
        main.rowconfigure(0, weight=1)

        # Columns
        self.listboxes = {}
        for i, status in enumerate(STATUSES):
            frame = ttk.Labelframe(main, text=STATUS_LABEL[status], style="Card.TLabelframe")
            frame.grid(row=0, column=i, sticky="nsew", padx=(0, 10 if i < 2 else 0))
            frame.rowconfigure(0, weight=1)
            frame.columnconfigure(0, weight=1)

            lb_frame = ttk.Frame(frame)
            lb_frame.grid(row=0, column=0, sticky="nsew")
            lb_frame.rowconfigure(0, weight=1)
            lb_frame.columnconfigure(0, weight=1)

            yscroll = ttk.Scrollbar(lb_frame, orient="vertical")
            yscroll.grid(row=0, column=1, sticky="ns")

            lb = tk.Listbox(lb_frame, height=20, activestyle="dotbox", yscrollcommand=yscroll.set)
            lb.grid(row=0, column=0, sticky="nsew")
            yscroll.config(command=lb.yview)

            lb.bind("<<ListboxSelect>>", lambda e, st=status: self.on_select(st))
            self.listboxes[status] = lb

        # Editor panel
        editor = ttk.Labelframe(main, text="Task Editor", style="Card.TLabelframe")
        editor.grid(row=0, column=3, sticky="nsew")
        editor.columnconfigure(0, weight=1)

        ttk.Label(editor, text="Title *").grid(row=0, column=0, sticky="w")
        self.title_var = tk.StringVar()
        self.title_entry = ttk.Entry(editor, textvariable=self.title_var)
        self.title_entry.grid(row=1, column=0, sticky="ew", pady=(4, 10))
        self.title_entry.bind("<KeyRelease>", lambda e: self._mark_draft_dirty())

        ttk.Label(editor, text="Description").grid(row=2, column=0, sticky="w")
        self.desc_text = tk.Text(editor, height=8, wrap="word")
        self.desc_text.grid(row=3, column=0, sticky="ew", pady=(4, 10))
        self.desc_text.bind("<KeyRelease>", lambda e: self._mark_draft_dirty())

        row4 = ttk.Frame(editor)
        row4.grid(row=4, column=0, sticky="ew", pady=(0, 10))
        ttk.Label(row4, text="Status").grid(row=0, column=0, sticky="w", padx=(0, 6))
        self.status_var = tk.StringVar(value="todo")
        cb_editor_status = ttk.Combobox(row4, textvariable=self.status_var, values=STATUSES,
                                        state="readonly", width=10)
        cb_editor_status.grid(row=0, column=1, sticky="w")
        cb_editor_status.bind("<<ComboboxSelected>>", lambda e: self._mark_draft_dirty())

        ttk.Label(row4, text="Priority").grid(row=0, column=2, sticky="w", padx=(16, 6))
        self.priority_var = tk.StringVar(value="medium")
        cb_editor_pr = ttk.Combobox(row4, textvariable=self.priority_var, values=PRIORITIES,
                                    state="readonly", width=10)
        cb_editor_pr.grid(row=0, column=3, sticky="w")
        cb_editor_pr.bind("<<ComboboxSelected>>", lambda e: self._mark_draft_dirty())

        ttk.Label(row4, text="Due (YYYY-MM-DD)").grid(row=1, column=0, sticky="w", pady=(10, 0))
        self.due_var = tk.StringVar(value="")
        due_entry = ttk.Entry(row4, textvariable=self.due_var, width=18)
        due_entry.grid(row=1, column=1, sticky="w", pady=(10, 0))
        due_entry.bind("<KeyRelease>", lambda e: self._mark_draft_dirty())

        self.pinned_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(row4, text="Pinned ⭐", variable=self.pinned_var,
                        command=self._mark_draft_dirty).grid(row=1, column=3, sticky="e", pady=(10, 0))

        btns = ttk.Frame(editor)
        btns.grid(row=5, column=0, sticky="ew")
        btns.columnconfigure((0, 1, 2), weight=1)

        ttk.Button(btns, text="New", style="Warning.TButton", command=self.new_task).grid(row=0, column=0, sticky="ew")
        ttk.Button(btns, text="Save", style="Success.TButton", command=self.save_task).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(btns, text="Delete", style="Danger.TButton", command=self.delete_task).grid(row=0, column=2, sticky="ew")

        move = ttk.Labelframe(editor, text="Move Selected Task", style="Card.TLabelframe")
        move.grid(row=6, column=0, sticky="ew", pady=(12, 0))
        move.columnconfigure((0, 1, 2), weight=1)

        ttk.Button(move, text="← To Do", command=lambda: self.move_to("todo")).grid(row=0, column=0, sticky="ew")
        ttk.Button(move, text="↔ Doing", command=lambda: self.move_to("doing")).grid(row=0, column=1, sticky="ew", padx=8)
        ttk.Button(move, text="→ Done", command=lambda: self.move_to("done")).grid(row=0, column=2, sticky="ew")

        self.status_line = tk.StringVar(value="Ready")
        ttk.Label(self, textvariable=self.status_line, anchor="w", padding=6).pack(side=tk.BOTTOM, fill=tk.X)

    # -------------------- SPECIAL FEATURES --------------------
    def _mark_draft_dirty(self):
        self._draft_dirty = True

    def _autosave_tick(self):
        try:
            if self._draft_dirty and self.selected_task_id is None:
                self._save_draft()
                self._draft_dirty = False
        except Exception:
            pass
        self.after(2000, self._autosave_tick)

    def _save_draft(self):
        draft = {
            "title": self.title_var.get(),
            "description": self.desc_text.get("1.0", tk.END).rstrip("\n"),
            "status": self.status_var.get(),
            "priority": self.priority_var.get(),
            "due_date": self.due_var.get(),
            "pinned": bool(self.pinned_var.get())
        }
        with open(DRAFT_PATH, "w", encoding="utf-8") as f:
            json.dump(draft, f, ensure_ascii=False, indent=2)
        self.status_line.set("Draft autosaved.")

    def _load_draft_if_any(self):
        if not os.path.exists(DRAFT_PATH):
            return
        try:
            with open(DRAFT_PATH, "r", encoding="utf-8") as f:
                draft = json.load(f)
            # Only load draft if editor is empty and no selected task
            if self.selected_task_id is None:
                self.title_var.set(draft.get("title", ""))
                self.desc_text.delete("1.0", tk.END)
                self.desc_text.insert(tk.END, draft.get("description", ""))
                self.status_var.set(draft.get("status", "todo") if draft.get("status") in STATUSES else "todo")
                self.priority_var.set(draft.get("priority", "medium") if draft.get("priority") in PRIORITIES else "medium")
                self.due_var.set(draft.get("due_date", ""))
                self.pinned_var.set(bool(draft.get("pinned", False)))
                self.status_line.set("Draft restored.")
        except Exception:
            pass

    def quick_add(self):
        raw = self.quick_var.get().strip()
        if not raw:
            return

        parsed = self._parse_quick_add(raw)
        if parsed is None:
            messagebox.showwarning("Quick Add", "Couldn't parse quick add text. Try a simpler format.")
            return

        title, desc, status, priority, due_date, pinned = parsed
        self.db.add_task(title, desc, status, priority, due_date, pinned=pinned)
        self.quick_var.set("")
        self.refresh()
        self.status_line.set("Quick task added.")

    def _parse_quick_add(self, text: str):
        """
        Examples:
          Finish report #high due:2026-02-10 @doing ⭐
          Buy milk #low @todo
          Read chapter due=2026-02-01
          Fix bug @done pinned
        Rules:
          #low/#medium/#high  -> priority
          @todo/@doing/@done  -> status
          due:YYYY-MM-DD or due=YYYY-MM-DD -> due_date
          'pinned' or '⭐' or 'star' -> pinned
          " - " splits title and description (optional)
        """
        t = text.strip()

        pinned = bool(re.search(r"(⭐|\bpinned\b|\bstar\b)", t, flags=re.IGNORECASE))

        # Status
        status = "todo"
        m = re.search(r"@(?P<s>todo|doing|done)\b", t, flags=re.IGNORECASE)
        if m:
            status = m.group("s").lower()

        # Priority
        priority = "medium"
        m = re.search(r"#(?P<p>low|medium|high)\b", t, flags=re.IGNORECASE)
        if m:
            priority = m.group("p").lower()

        # Due date
        due_date = None
        m = re.search(r"\bdue[:=](\d{4}-\d{2}-\d{2})\b", t, flags=re.IGNORECASE)
        if m:
            candidate = m.group(1)
            try:
                datetime.date.fromisoformat(candidate)
                due_date = candidate
            except ValueError:
                due_date = None

        # Remove tokens from title/desc
        cleaned = re.sub(r"@(?:todo|doing|done)\b", "", t, flags=re.IGNORECASE)
        cleaned = re.sub(r"#(?:low|medium|high)\b", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\bdue[:=]\d{4}-\d{2}-\d{2}\b", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"(⭐|\bpinned\b|\bstar\b)", "", cleaned, flags=re.IGNORECASE)
        cleaned = " ".join(cleaned.split()).strip()

        if not cleaned:
            return None

        # Optional split title - description
        if " - " in cleaned:
            title, desc = cleaned.split(" - ", 1)
        else:
            title, desc = cleaned, ""

        title = title.strip()
        desc = desc.strip()
        if not title:
            return None

        if status not in STATUSES:
            status = "todo"
        if priority not in PRIORITIES:
            priority = "medium"

        return title, desc, status, priority, due_date, pinned

    # -------------------- Helpers --------------------
    def clear_search(self):
        self.search_var.set("")
        self.refresh()

    def validate_due(self, due_str):
        due_str = due_str.strip()
        if not due_str:
            return None
        try:
            datetime.date.fromisoformat(due_str)
            return due_str
        except ValueError:
            return "INVALID"

    def _deadline_state(self, due_date_str: str | None):
        """
        Return:
          "overdue" if due < today
          "soon"    if due within next 2 days
          "ok"      otherwise or no due date
        """
        if not due_date_str:
            return "ok"
        try:
            due = datetime.date.fromisoformat(due_date_str)
        except ValueError:
            return "ok"

        today = datetime.date.today()
        if due < today:
            return "overdue"
        if today <= due <= (today + datetime.timedelta(days=2)):
            return "soon"
        return "ok"

    def refresh(self):
        for lb in self.listboxes.values():
            lb.delete(0, tk.END)

        search = self.search_var.get().strip() or None
        status_filter = self.filter_status.get()
        priority_filter = self.filter_priority.get()
        pinned_only = bool(self.pinned_only_var.get())
        sort_sel = self.sort_var.get()

        sort_map = {"updated": "updated_at", "created": "created", "deadline": "deadline", "title": "title"}
        sort_by = sort_map.get(sort_sel, "updated_at")

        rows = self.db.list_tasks(
            search=search,
            status=status_filter,
            priority=priority_filter,
            pinned_only=pinned_only,
            sort=sort_by
        )

        # Dashboard
        total = len(rows)
        counts = {"todo": 0, "doing": 0, "done": 0}
        for r in rows:
            counts[r[3]] += 1
        done_pct = int((counts["done"] / total) * 100) if total else 0
        self.dash_var.set(
            f"Total: {total} | To Do: {counts['todo']} | Doing: {counts['doing']} | Done: {counts['done']} | Done%: {done_pct}%"
        )

        # Build per status
        self._index = {st: [] for st in STATUSES}
        for r in rows:
            task_id, title, desc, status, priority, due, pinned, created, updated = r

            pin = "⭐ " if pinned else ""
            due_tag = ""
            state = self._deadline_state(due)

            if due:
                if state == "overdue":
                    due_tag = f"  [OVERDUE {due}]"
                elif state == "soon":
                    due_tag = f"  [DUE SOON {due}]"
                else:
                    due_tag = f"  [due {due}]"

            display = f"{pin}[{priority}] {title}{due_tag}"

            lb = self.listboxes[status]
            idx = lb.size()
            lb.insert(tk.END, display)

            # Color highlight (Listbox itemconfig)
            if state == "overdue":
                lb.itemconfig(idx, fg="#c0392b")  # red
            elif state == "soon":
                lb.itemconfig(idx, fg="#b9770e")  # orange

            self._index[status].append(task_id)

        self.status_line.set(f"{len(rows)} task(s) loaded.")

    def on_select(self, status):
        lb = self.listboxes[status]
        sel = lb.curselection()
        if not sel:
            return
        idx = sel[0]
        task_id = self._index[status][idx]

        # Clear selection in other listboxes
        for st, other in self.listboxes.items():
            if st != status:
                other.selection_clear(0, tk.END)

        self.selected_task_id = task_id
        self.selected_status = status
        self.load_task(task_id)

    def load_task(self, task_id):
        t = self.db.get_task(task_id)
        if not t:
            return
        _, title, desc, status, priority, due, pinned, created, updated = t

        self.title_var.set(title)
        self.desc_text.delete("1.0", tk.END)
        self.desc_text.insert(tk.END, desc or "")
        self.status_var.set(status)
        self.priority_var.set(priority)
        self.due_var.set(due or "")
        self.pinned_var.set(bool(pinned))

        self._draft_dirty = False
        self.status_line.set(f"Loaded task id={task_id}")

    def new_task(self):
        self.selected_task_id = None
        self.selected_status = None
        for lb in self.listboxes.values():
            lb.selection_clear(0, tk.END)

        self.title_var.set("")
        self.desc_text.delete("1.0", tk.END)
        self.status_var.set("todo")
        self.priority_var.set("medium")
        self.due_var.set("")
        self.pinned_var.set(False)

        self.title_entry.focus_set()
        self._mark_draft_dirty()
        self.status_line.set("New task (draft).")

    def save_task(self):
        title = self.title_var.get().strip()
        if not title:
            messagebox.showwarning("Validation", "Title is required.")
            return

        desc = self.desc_text.get("1.0", tk.END).rstrip("\n")
        status = self.status_var.get()
        priority = self.priority_var.get()
        due = self.validate_due(self.due_var.get())
        pinned = bool(self.pinned_var.get())

        if due == "INVALID":
            messagebox.showwarning("Validation", "Due date must be YYYY-MM-DD (or empty).")
            return

        if self.selected_task_id is None:
            self.db.add_task(title, desc, status, priority, due, pinned=pinned)
            self.status_line.set("Task added.")
        else:
            self.db.update_task(self.selected_task_id, title, desc, status, priority, due, pinned=pinned)
            self.status_line.set("Task updated.")

        # Once saved, draft isn't needed
        self._draft_dirty = False
        try:
            if os.path.exists(DRAFT_PATH):
                os.remove(DRAFT_PATH)
        except Exception:
            pass

        self.refresh()
        self.new_task()

    def delete_task(self):
        if self.selected_task_id is None:
            messagebox.showinfo("Delete", "No task selected.")
            return
        if messagebox.askyesno("Delete", "Delete selected task?"):
            self.db.delete_task(self.selected_task_id)
            self.status_line.set(f"Deleted task id={self.selected_task_id}")
            self.refresh()
            self.new_task()

    def move_to(self, new_status):
        if self.selected_task_id is None:
            messagebox.showinfo("Move", "Select a task first.")
            return

        t = self.db.get_task(self.selected_task_id)
        if not t:
            return

        task_id, title, desc, old_status, priority, due, pinned, created, updated = t
        self.db.update_task(task_id, title, desc or "", new_status, priority, due, pinned=pinned)
        self.status_line.set(f"Moved task id={task_id} to {STATUS_LABEL[new_status]}")
        self.refresh()

    def export_csv(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not path:
            return

        rows = self.db.list_tasks(
            search=self.search_var.get().strip() or None,
            status=self.filter_status.get(),
            priority=self.filter_priority.get(),
            pinned_only=bool(self.pinned_only_var.get()),
            sort="updated_at"
        )

        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["id", "title", "description", "status", "priority", "due_date", "pinned", "created_at", "updated_at"])
            for r in rows:
                w.writerow(r)

        messagebox.showinfo("Export", "Export completed successfully.")

    def on_close(self):
        # save draft on exit only if unsaved new task
        try:
            if self.selected_task_id is None:
                self._save_draft()
        except Exception:
            pass

        try:
            self.db.close()
        except Exception:
            pass
        self.destroy()


if __name__ == "__main__":
    app = TaskBoardApp()
    app.mainloop()