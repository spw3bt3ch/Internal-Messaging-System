import tkinter as tk
from tkinter import ttk, messagebox
import sqlite3
from datetime import datetime

# Setup database
conn = sqlite3.connect("email_app.db")
cursor = conn.cursor()

cursor.execute('''CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password TEXT NOT NULL
)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sender TEXT,
    recipient TEXT,
    content TEXT,
    timestamp TEXT
)''')
conn.commit()

class EmailApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Internal Mail App")
        self.root.geometry("700x600")
        self.root.configure(bg="#f0f4f7")
        self.current_user = None

        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', font=('Segoe UI', 11))
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), background='#4CAF50', foreground='white')
        style.map('TButton', background=[('active', '#45a049')])
        style.configure('Header.TLabel', font=('Segoe UI', 16, 'bold'), foreground="#333", background="#f0f4f7")

        self.show_login()

    def clear(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def show_login(self):
        self.clear()
        ttk.Label(self.root, text="🔐 Login", style='Header.TLabel').pack(pady=20)

        username = ttk.Entry(self.root)
        password = ttk.Entry(self.root, show='*')

        ttk.Label(self.root, text="Username").pack()
        username.pack(pady=5)
        ttk.Label(self.root, text="Password").pack()
        password.pack(pady=5)

        def login():
            u = username.get().strip()
            p = password.get().strip()
            cursor.execute("SELECT * FROM users WHERE username=? AND password=?", (u, p))
            if cursor.fetchone():
                self.current_user = u
                self.show_menu()
            else:
                messagebox.showerror("Error", "Invalid credentials")

        ttk.Button(self.root, text="Login", command=login).pack(pady=10)
        ttk.Button(self.root, text="Go to Register", command=self.show_register).pack()

    def show_register(self):
        self.clear()
        ttk.Label(self.root, text="📝 Register", style='Header.TLabel').pack(pady=20)

        username = ttk.Entry(self.root)
        password = ttk.Entry(self.root, show='*')

        ttk.Label(self.root, text="Choose Username").pack()
        username.pack(pady=5)
        ttk.Label(self.root, text="Choose Password").pack()
        password.pack(pady=5)

        def register():
            u = username.get().strip()
            p = password.get().strip()
            if not u or not p:
                messagebox.showerror("Error", "All fields required.")
                return
            try:
                cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (u, p))
                conn.commit()
                messagebox.showinfo("Success", "Registration complete.")
                self.show_login()
            except sqlite3.IntegrityError:
                messagebox.showerror("Error", "Username already exists.")

        ttk.Button(self.root, text="Register", command=register).pack(pady=10)
        ttk.Button(self.root, text="Back to Login", command=self.show_login).pack()

    def show_menu(self):
        self.clear()
        ttk.Label(self.root, text=f"📫 Welcome, {self.current_user}", style='Header.TLabel').pack(pady=20)

        ttk.Button(self.root, text="📨 Send Message", command=self.show_send_page).pack(pady=10)
        ttk.Button(self.root, text="📥 Inbox", command=self.show_inbox).pack(pady=10)
        ttk.Button(self.root, text="📤 Outbox", command=self.show_outbox).pack(pady=10)
        ttk.Button(self.root, text="🚪 Logout", command=self.logout).pack(pady=20)

    def show_send_page(self):
        self.clear()
        ttk.Label(self.root, text="✉️ Send Message", style='Header.TLabel').pack(pady=20)

        recipient = ttk.Entry(self.root)
        message = tk.Text(self.root, height=10, width=60)

        ttk.Label(self.root, text="To:").pack()
        recipient.pack(pady=5)
        ttk.Label(self.root, text="Message:").pack()
        message.pack(pady=5)

        def send():
            to_user = recipient.get().strip()
            msg = message.get("1.0", tk.END).strip()
            if not to_user or not msg:
                messagebox.showerror("Error", "All fields are required.")
                return
            cursor.execute("SELECT * FROM users WHERE username=?", (to_user,))
            if not cursor.fetchone():
                messagebox.showerror("Error", "Recipient does not exist.")
                return
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            cursor.execute("INSERT INTO messages (sender, recipient, content, timestamp) VALUES (?, ?, ?, ?)",
                           (self.current_user, to_user, msg, timestamp))
            conn.commit()
            messagebox.showinfo("Success", "Message sent.")
            self.show_menu()

        ttk.Button(self.root, text="Send", command=send).pack(pady=10)
        ttk.Button(self.root, text="Back", command=self.show_menu).pack()

    def show_inbox(self):
        self.clear()
        ttk.Label(self.root, text="📥 Inbox", style='Header.TLabel').pack(pady=10)

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        cursor.execute("SELECT id, sender, content, timestamp FROM messages WHERE recipient=? ORDER BY id DESC", (self.current_user,))
        messages = cursor.fetchall()

        for mid, sender, content, timestamp in messages:
            msg_frame = ttk.LabelFrame(scroll_frame, text=f"From: {sender} | {timestamp}", padding=10)
            msg_frame.pack(fill="x", padx=10, pady=5)
            ttk.Label(msg_frame, text=content, wraplength=600).pack()
            ttk.Button(msg_frame, text="Delete", command=lambda m=mid: self.delete_message(m)).pack(pady=5)

        ttk.Button(self.root, text="Back", command=self.show_menu).pack(pady=10)

    def show_outbox(self):
        self.clear()
        ttk.Label(self.root, text="📤 Outbox", style='Header.TLabel').pack(pady=10)

        frame = ttk.Frame(self.root)
        frame.pack(fill="both", expand=True)

        canvas = tk.Canvas(frame)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scroll_frame = ttk.Frame(canvas)

        scroll_frame.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
        canvas.create_window((0, 0), window=scroll_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        cursor.execute("SELECT id, recipient, content, timestamp FROM messages WHERE sender=? ORDER BY id DESC", (self.current_user,))
        messages = cursor.fetchall()

        for mid, recipient, content, timestamp in messages:
            msg_frame = ttk.LabelFrame(scroll_frame, text=f"To: {recipient} | {timestamp}", padding=10)
            msg_frame.pack(fill="x", padx=10, pady=5)
            ttk.Label(msg_frame, text=content, wraplength=600).pack()
            ttk.Button(msg_frame, text="Delete", command=lambda m=mid: self.delete_message(m)).pack(pady=5)

        ttk.Button(self.root, text="Back", command=self.show_menu).pack(pady=10)

    def delete_message(self, msg_id):
        cursor.execute("DELETE FROM messages WHERE id=?", (msg_id,))
        conn.commit()
        messagebox.showinfo("Deleted", "Message deleted successfully.")
        self.show_menu()

    def logout(self):
        self.current_user = None
        self.show_login()

if __name__ == "__main__":
    root = tk.Tk()
    app = EmailApp(root)
    root.mainloop()
