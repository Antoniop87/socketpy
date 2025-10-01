import socket
import json
import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import hashlib


import urllib.request
import urllib.error
from urllib.parse import urlencode

HOST = "127.0.0.1"
PORT = 65432

selected_file_path = None
selected_file_name = None
current_user = None
protocol = None  

def calc_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()




def send_request(action, data):
    try:
        message = {"action": action, **data}
        encoded = json.dumps(message).encode("utf-8")
        response = None

        if protocol == "tcp":
            
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((HOST, PORT))
                s.sendall(encoded)

                full_data = b""
                while True:
                    packet = s.recv(4096)
                    if not packet:
                        break
                    full_data += packet
                    try:
                        
                        response = json.loads(full_data.decode("utf-8"))
                        return response
                    except json.JSONDecodeError:
                        continue
                if response is None:
                    raise Exception("Resposta TCP incompleta ou vazia.")


        elif protocol == "udp":
            
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(20) 
                s.sendto(encoded, (HOST, PORT))
                data, _ = s.recvfrom(65535)
                response = json.loads(data.decode("utf-8"))
                return response

        
        elif protocol == "http":
            
            url = f"http://{HOST}:{PORT}/api"
            
            req = urllib.request.Request(
                url, 
                data=encoded, 
                headers={"Content-Type": "application/json"}, 
                method="POST"
            )
            
            try:
                
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_data = resp.read()
                    response = json.loads(resp_data.decode("utf-8"))
                    return response
            except urllib.error.HTTPError as he:
                
                try:
                    
                    err_data = he.read().decode("utf-8")
                    return json.loads(err_data)
                except:
                    
                    return {"status": "error", "message": f"Erro HTTP {he.code}: Falha ao processar a resposta de erro."}
            except Exception as e:
                messagebox.showerror("Erro de Conexão", f"Erro HTTP: {e}")
                return {"status": "error", "message": "Erro de conexão HTTP."}

    except Exception as e:
        messagebox.showerror("Erro de Conexão", f"Não foi possível conectar ao servidor: {e}")
        return {"status": "error", "message": "Erro de conexão."}








def try_login():
    global current_user
    username = entry_login_user.get()
    password = entry_login_pass.get()

    response = send_request("login", {"username": username, "password": password})
    if response.get("status") == "success":
        current_user = username
        show_main_frame()
        messagebox.showinfo("Sucesso", response.get("message", "OK"))
    else:
        messagebox.showerror("Erro de Login", response.get("message", "Erro desconhecido."))

def try_register():
    username = entry_register_user.get()
    password = entry_register_pass.get()

    if not username or not password:
        messagebox.showerror("Erro", "Por favor, preencha todos os campos.")
        return

    response = send_request("register", {"username": username, "password": password})
    if response.get("status") == "success":
        messagebox.showinfo("Sucesso", response.get("message", "OK"))
        show_login_frame()
    else:
        messagebox.showerror("Erro de Registro", response.get("message", "Erro desconhecido."))

def send_data():
    global selected_file_path
    if not selected_file_path:
        messagebox.showerror("Erro", "Por favor, selecione um arquivo.")
        return

    try:
        with open(selected_file_path, "rb") as file:
            file_data = file.read()
            file_data_base64 = base64.b64encode(file_data).decode("utf-8")
            checksum = calc_md5(file_data)

        message = {
            "username": current_user,
            "file_data": file_data_base64,
            "file_type": os.path.splitext(selected_file_path)[1],
            "checksum": checksum,
        }

        response = send_request("upload", message)
        if response.get("status") == "success":
            messagebox.showinfo("Sucesso", response.get("message", "OK"))
            fetch_data()
        else:
            messagebox.showerror("Erro de Envio", response.get("message", "Erro desconhecido."))
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao enviar dados: {e}")

def fetch_data():
    response = send_request("list_data", {})
    if isinstance(response, list):
        for item in tree.get_children():
            tree.delete(item)
        for item in response:
            tree.insert("", tk.END, values=(item["id"], item["name"], item["file_type"], item["date"]))
    else:
        messagebox.showerror("Erro", response.get("message", "Erro desconhecido."))

def select_file():
    global selected_file_path, selected_file_name
    file_path = filedialog.askopenfilename(
        title="Selecione um arquivo (imagem ou PDF)",
        filetypes=[("Todos os Arquivos", "*.*"), ("Imagens", "*.jpg *.jpeg *.png"), ("Arquivos PDF", "*.pdf")],
    )
    if file_path:
        selected_file_path = file_path
        selected_file_name = os.path.basename(file_path)
        label_file.config(text=f"Arquivo selecionado: {selected_file_name}")

def download_file():
    selected_item = tree.focus()
    if not selected_item:
        messagebox.showwarning("Aviso", "Selecione um item.")
        return

    item_values = tree.item(selected_item, "values")
    file_id = item_values[0]

    response = send_request("download", {"id": file_id})
    if response.get("status") == "success":
        file_data_base64 = response["file_data"]
        sender_name = response["name"]
        file_type = response["file_type"]
        checksum = response["checksum"]

        file_data = base64.b64decode(file_data_base64)
        if calc_md5(file_data) != checksum:
            messagebox.showerror("Erro", "Checksum inválido! Arquivo corrompido.")
            return

        save_path = filedialog.asksaveasfilename(
            initialfile=f"{sender_name}_arquivo{file_type}",
            defaultextension=file_type,
            title="Salvar arquivo",
        )
        if save_path:
            with open(save_path, "wb") as f:
                f.write(file_data)
            messagebox.showinfo("Sucesso", "Arquivo salvo com sucesso!")
    else:
        messagebox.showerror("Erro", response.get("message", "Erro desconhecido."))

def show_login_frame():
    main_frame.pack_forget()
    login_frame.pack(fill="both", expand=True)

def show_main_frame():
    login_frame.pack_forget()
    main_frame.pack(fill="both", expand=True)
    fetch_data()




protocol = input("Escolha protocolo (tcp/udp/http): ").strip().lower()
if protocol not in ["tcp", "udp", "http"]:
    print("Protocolo inválido, saindo...")
    exit(1)




root = tk.Tk()
root.title(f"Cliente {protocol.upper()} - Autenticação e Envio")
root.geometry("800x600")

login_frame = tk.Frame(root)
main_frame = tk.Frame(root)

login_lbl = tk.Label(login_frame, text="Faça Login ou Registre-se", font=("Arial", 16))
login_lbl.pack(pady=20)

tk.Label(login_frame, text="Nome de Usuário:").pack()
entry_login_user = tk.Entry(login_frame)
entry_login_user.pack(pady=5)

tk.Label(login_frame, text="Senha:").pack()
entry_login_pass = tk.Entry(login_frame, show="*")
entry_login_pass.pack(pady=5)

btn_login = tk.Button(login_frame, text="Login", command=try_login)
btn_login.pack(pady=10)

tk.Label(login_frame, text="Ainda não tem uma conta?").pack(pady=10)
tk.Label(login_frame, text="Nome de Usuário:").pack()
entry_register_user = tk.Entry(login_frame)
entry_register_user.pack(pady=5)

tk.Label(login_frame, text="Senha:").pack()
entry_register_pass = tk.Entry(login_frame, show="*")
entry_register_pass.pack(pady=5)

btn_register = tk.Button(login_frame, text="Registrar", command=try_register)
btn_register.pack(pady=10)

frame_send = tk.LabelFrame(main_frame, text="Enviar Dados", padx=10, pady=10)
frame_send.pack(pady=10, padx=10, fill="x")

btn_select_file = tk.Button(frame_send, text="Selecionar Arquivo", command=select_file)
btn_select_file.grid(row=1, column=0, padx=5, pady=5, sticky="w")
label_file = tk.Label(frame_send, text="Nenhum arquivo selecionado.", wraplength=400)
label_file.grid(row=1, column=1, padx=5, pady=5, sticky="w")
btn_send = tk.Button(frame_send, text="Enviar", command=send_data)
btn_send.grid(row=2, column=0, columnspan=2, pady=10)

frame_display = tk.LabelFrame(main_frame, text="Arquivos Disponíveis", padx=10, pady=10)
frame_display.pack(pady=10, padx=10, fill="both", expand=True)

frame_buttons = tk.Frame(frame_display)
frame_buttons.pack(pady=5)
btn_refresh = tk.Button(frame_buttons, text="Atualizar Lista", command=fetch_data)
btn_refresh.pack(side=tk.LEFT, padx=5)
btn_download = tk.Button(frame_buttons, text="Baixar", command=download_file)
btn_download.pack(side=tk.LEFT, padx=5)

columns = ("id", "sender", "file_type", "date")
tree = ttk.Treeview(frame_display, columns=columns, show="headings")
tree.heading("sender", text="Nome")
tree.heading("file_type", text="Tipo de Arquivo")
tree.heading("date", text="Data de Envio")
tree.column("id", width=0, stretch=tk.NO)
tree.column("sender", width=200)
tree.column("file_type", width=150)
tree.column("date", width=200)
tree.pack(fill="both", expand=True)

show_login_frame()
root.mainloop()