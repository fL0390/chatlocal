import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import socket
import threading
import struct
import base64
import json
import os
import sys
import requests
from PIL import Image, ImageTk
import io

# Configuration
VERSION = "1.4"
CONFIG_FILE = "chat_config.json"
GITHUB_RAW_URL = "https://raw.githubusercontent.com/yourusername/yourrepo/main/yourscript.py"


class DarkChatWithUpdates:
    def __init__(self, master):
        self.master = master
        master.title(f"Dark Chat v{VERSION}")
        self.set_dark_theme()

        # Load or create config
        self.config = self.load_config()

        # GUI Setup
        self.create_widgets()

        # Network Setup
        self.multicast_group = ('224.1.1.1', 5000)
        self.setup_socket()

        # Start threads
        self.running = True
        self.start_threads()

        # Handle window closing
        master.protocol("WM_DELETE_WINDOW", self.on_close)

        # Check for updates (will fail gracefully if no internet)
        self.check_for_updates()

    def set_dark_theme(self):
        self.bg_color = "#2a2a2a"
        self.fg_color = "#ffffff"
        self.entry_bg = "#333333"
        self.button_bg = "#4a4a4a"
        self.button_active = "#666666"

        self.master.configure(bg=self.bg_color)
        self.master.option_add("*TButton*highlightBackground", self.bg_color)

    def create_widgets(self):
        # Name Entry with saved name
        self.name_frame = tk.Frame(self.master, bg=self.bg_color)
        self.name_frame.pack(padx=5, pady=5, fill='x')

        tk.Label(self.name_frame, text="Name:", bg=self.bg_color, fg=self.fg_color
                 ).pack(side='left')
        self.name_entry = tk.Entry(self.name_frame, bg=self.entry_bg, fg=self.fg_color,
                                   insertbackground=self.fg_color)
        self.name_entry.pack(side='left', fill='x', expand=True)
        self.name_entry.insert(0, self.config.get("username", "Anonymous"))
        self.name_entry.bind("<FocusOut>", self.save_name)

        # Chat History
        self.chat_history = scrolledtext.ScrolledText(self.master,
                                                      bg=self.entry_bg,
                                                      fg=self.fg_color,
                                                      insertbackground=self.fg_color,
                                                      state='disabled')
        self.chat_history.pack(padx=5, pady=5, fill='both', expand=True)

        # Message Entry and Buttons
        self.msg_frame = tk.Frame(self.master, bg=self.bg_color)
        self.msg_frame.pack(padx=5, pady=5, fill='x')

        self.msg_entry = tk.Entry(self.msg_frame, bg=self.entry_bg, fg=self.fg_color,
                                  insertbackground=self.fg_color)
        self.msg_entry.pack(side='left', fill='x', expand=True)
        self.msg_entry.bind("<Return>", self.send_message)

        send_btn = tk.Button(self.msg_frame, text="Send", command=self.send_message,
                             bg=self.button_bg, fg=self.fg_color, activebackground=self.button_active,
                             activeforeground=self.fg_color, relief='flat')
        send_btn.pack(side='left', padx=(5, 0))

        image_btn = tk.Button(self.msg_frame, text="📷", command=self.send_image,
                              bg=self.button_bg, fg=self.fg_color, activebackground=self.button_active,
                              activeforeground=self.fg_color, relief='flat')
        image_btn.pack(side='left', padx=(5, 0))

    def setup_socket(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
        self.sock.bind(('', 5000))

        group = socket.inet_aton('224.1.1.1')
        mreq = struct.pack('4sL', group, socket.INADDR_ANY)
        self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    def start_threads(self):
        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.daemon = True
        self.receive_thread.start()

    def load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}")
        return {"username": "Anonymous"}

    def save_config(self):
        try:
            with open(CONFIG_FILE, 'w') as f:
                json.dump(self.config, f)
        except Exception as e:
            print(f"Error saving config: {e}")

    def save_name(self, event=None):
        self.config["username"] = self.name_entry.get().strip()
        self.save_config()

    def check_for_updates(self):
        def update_check():
            try:
                response = requests.get(GITHUB_RAW_URL, timeout=5)
                remote_code = response.text
                remote_version = self.extract_version(remote_code)

                if remote_version > VERSION:
                    self.master.after(0, self.prompt_update, remote_version)
            except requests.exceptions.RequestException:
                print("Update check failed (no internet connection)")
            except Exception as e:
                print(f"Update check error: {e}")

        threading.Thread(target=update_check, daemon=True).start()

    def extract_version(self, code):
        for line in code.split('\n'):
            if line.startswith("VERSION ="):
                return line.split('"')[1]
        return "0.0"

    def prompt_update(self, new_version):
        answer = messagebox.askyesno(
            "Update Available",
            f"New version {new_version} available!\nUpdate now? (Application will restart)"
        )
        if answer:
            self.perform_update()

    def perform_update(self):
        try:
            response = requests.get(GITHUB_RAW_URL, timeout=10)
            with open(__file__, 'w') as f:
                f.write(response.text)

            messagebox.showinfo(
                "Update Complete",
                "Application will now restart to apply changes"
            )
            os.execl(sys.executable, sys.executable, *sys.argv)
        except Exception as e:
            messagebox.showerror("Update Failed", str(e))

    def receive_messages(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(65535)
                message = data.decode()

                if message.startswith("IMAGE:"):
                    self.handle_image(message)
                else:
                    self.display_message(message)
            except OSError:
                break

    def handle_image(self, message):
        try:
            parts = message.split(":", 2)
            if len(parts) != 3:
                raise ValueError("Invalid image format")

            name = parts[1]
            img_data = base64.b64decode(parts[2])
            self.display_image(name, img_data)
        except Exception as e:
            print(f"Error handling image: {e}\nOriginal message: {message[:100]}")

    def display_message(self, message):
        self.chat_history.configure(state='normal')
        self.chat_history.insert('end', message + '\n')
        self.chat_history.configure(state='disabled')
        self.chat_history.see('end')

    def display_image(self, sender, img_data):
        try:
            image = Image.open(io.BytesIO(img_data))
            image.thumbnail((400, 400))
            photo = ImageTk.PhotoImage(image)

            self.chat_history.configure(state='normal')
            self.chat_history.image_create('end', image=photo)
            self.chat_history.insert('end', f'\n{sender} sent an image\n\n')
            self.chat_history.configure(state='disabled')
            self.chat_history.see('end')

            self.chat_history.image = photo
        except Exception as e:
            print(f"Error displaying image: {e}")

    def send_message(self, event=None):
        name = self.name_entry.get().strip()
        message = self.msg_entry.get().strip()
        if message:
            full_msg = f"{name}: {message}"
            self.sock.sendto(full_msg.encode(), self.multicast_group)
            self.msg_entry.delete(0, 'end')

    def send_image(self):
        file_path = filedialog.askopenfilename(filetypes=[
            ("Image Files", "*.png *.jpg *.jpeg *.gif")
        ])

        if file_path:
            try:
                with open(file_path, "rb") as f:
                    img_data = f.read()

                base64_img = base64.b64encode(img_data).decode()
                name = self.name_entry.get().strip()
                message = f"IMAGE:{name}:{base64_img}"
                self.sock.sendto(message.encode(), self.multicast_group)
            except Exception as e:
                print(f"Error sending image: {e}")

    def on_close(self):
        self.running = False
        self.sock.close()
        self.master.destroy()


if __name__ == "__main__":
    root = tk.Tk()
    app = DarkChatWithUpdates(root)
    root.mainloop()