import tkinter as tk
from tkinter import messagebox

users = {}
attempts = 3

def check_password_strength(password):
    if len(password) < 8:
        return "Password must be at least 8 characters long."
    
    has_upper = any(ch.isupper() for ch in password)
    has_lower = any(ch.islower() for ch in password)
    has_digit = any(ch.isdigit() for ch in password)
    has_special = any(ch in "@#$&*?!" for ch in password)

    if not has_upper:
        return "Password must contain at least one uppercase letter."
    if not has_lower:
        return "Password must contain at least one lowercase letter."
    if not has_digit:
        return "Password must contain at least one digit."
    if not has_special:
        return "Password must contain at least one special character (@#$&*?!)."
    
    return "Strong"


def register_user():
    username = entry_user.get().strip()
    password = entry_pass.get().strip()

    if username == "" or password == "":
        messagebox.showwarning("Warning", "Both username and password are required!")
        return
    
    if not human_check.get():
        messagebox.showwarning("Verification", "Please confirm you are human!")
        return
    
    if username in users:
        messagebox.showerror("Error", "Username already exists!")
        return
    
    strength = check_password_strength(password)
    if strength != "Strong":
        messagebox.showwarning("Weak Password", strength)
        return
    
    users[username] = password
    messagebox.showinfo("Success", "User registered successfully!")
    human_check.set(0)


def login_user():
    global attempts
    username = entry_user.get().strip()
    password = entry_pass.get().strip()

    if username == "" or password == "":
        messagebox.showwarning("Warning", "Please enter both username and password!")
        return

    if attempts <= 0:
        messagebox.showerror("Locked", "Too many failed attempts. Try again later.")
        return

    if username in users and users[username] == password:
        messagebox.showinfo("Welcome", f"Welcome back, {username}!")
        attempts = 3
    else:
        attempts -= 1
        messagebox.showerror("Login Failed", f"Invalid username or password.\nAttempts left: {attempts}")
    human_check.set(0)



root = tk.Tk()
root.title("Smart Login System")
root.geometry("430x420")
root.resizable(False, False)
root.config(bg="#1a1a2e")

tk.Label(
    root,
    text="SMART LOGIN SYSTEM",
    font=("Helvetica", 18, "bold"),
    bg="#1a1a2e",
    fg="#00ffff"
).pack(pady=20)

tk.Label(
    root,
    text="Username:",
    font=("Arial", 12, "bold"),
    bg="#1a1a2e",
    fg="#f5f5f5"
).pack(pady=5)

entry_user = tk.Entry(
    root,
    width=30,
    font=("Consolas", 11),
    bd=3,
    relief="solid",
    bg="#f0f0f0",
    fg="#000000"
)
entry_user.pack(pady=5)

tk.Label(
    root,
    text="Password:",
    font=("Arial", 12, "bold"),
    bg="#1a1a2e",
    fg="#f5f5f5"
).pack(pady=5)

entry_pass = tk.Entry(
    root,
    show="*",
    width=30,
    font=("Consolas", 11),
    bd=3,
    relief="solid",
    bg="#f0f0f0",
    fg="#000000"
)
entry_pass.pack(pady=5)

human_check = tk.IntVar()
tk.Checkbutton(
    root,
    text="I'm not a robot 🤖",
    variable=human_check,
    onvalue=1,
    offvalue=0,
    bg="#1a1a2e",
    fg="#00ff99",
    selectcolor="#1a1a2e",
    font=("Arial", 11, "bold"),
    activebackground="#1a1a2e",
    activeforeground="#00ff99"
).pack(pady=10)

frame = tk.Frame(root, bg="#1a1a2e")
frame.pack(pady=25)

btn_login = tk.Button(
    frame,
    text="Login",
    width=12,
    font=("Arial", 11, "bold"),
    bg="#00b894",
    fg="white",
    bd=4,
    relief="raised",
    activebackground="#019870",
    activeforeground="white",
    command=login_user
)
btn_login.grid(row=0, column=0, padx=10)

btn_register = tk.Button(
    frame,
    text="Register",
    width=12,
    font=("Arial", 11, "bold"),
    bg="#0984e3",
    fg="white",
    bd=4,
    relief="raised",
    activebackground="#0652DD",
    activeforeground="white",
    command=register_user
)
btn_register.grid(row=0, column=1, padx=10)

tk.Label(
    root,
    text="© 2025 Smart Login | Human Verification Enabled",
    font=("Arial", 9),
    bg="#1a1a2e",
    fg="#aaaaaa"
).pack(side="bottom", pady=10)

root.mainloop()
