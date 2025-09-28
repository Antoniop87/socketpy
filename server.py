import socket
import threading
import json
import psycopg2
import base64
from datetime import datetime
import hashlib

HOST = "127.0.0.1"
PORT = 65432
DB_PARAMS = {
    "dbname": "socketpy",
    "user": "postgres",
    "password": "postgres",
    "host": "localhost",
    "port": 5432,
}




def get_db_connection():
    try:
        return psycopg2.connect(**DB_PARAMS)
    except Exception as e:
        print(f"Erro ao conectar ao banco de dados: {e}")
        return None

def hash_password(password):
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def check_password(hashed_password, user_password):
    return hashed_password == hash_password(user_password)

def calc_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()




def process_request(request, is_udp=False, addr=None, udp_socket=None):
    action = request.get("action")

    
    if action == "register":
        username = request["username"]
        password = request["password"]
        hashed_pw = hash_password(password)

        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor()
            try:
                cursor.execute(
                    "INSERT INTO users (username, password) VALUES (%s, %s)",
                    (username, hashed_pw),
                )
                db_conn.commit()
                response = {"status": "success", "message": "Registro bem-sucedido!"}
            except psycopg2.errors.UniqueViolation:
                db_conn.rollback()
                response = {"status": "error", "message": "Nome de usuário já existe."}
            except Exception as e:
                print(f"Erro ao registrar usuário: {e}")
                db_conn.rollback()
                response = {"status": "error", "message": "Erro no registro."}
            finally:
                cursor.close()
                db_conn.close()
        else:
            response = {"status": "error", "message": "Falha na conexão com DB."}

    
    elif action == "login":
        username = request["username"]
        password = request["password"]

        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor()
            try:
                cursor.execute("SELECT password FROM users WHERE username = %s", (username,))
                user_data = cursor.fetchone()

                if user_data and check_password(user_data[0], password):
                    response = {"status": "success", "message": "Login bem-sucedido!"}
                else:
                    response = {"status": "error", "message": "Usuário ou senha inválidos."}
            except Exception as e:
                print(f"Erro no login: {e}")
                response = {"status": "error", "message": "Erro no servidor."}
            finally:
                cursor.close()
                db_conn.close()
        else:
            response = {"status": "error", "message": "Falha na conexão com DB."}

    
    elif action == "upload":
        username = request["username"]
        file_data_base64 = request["file_data"]
        file_type = request["file_type"]
        checksum_client = request["checksum"]

        file_data = base64.b64decode(file_data_base64)
        checksum_server = calc_md5(file_data)

        if checksum_client != checksum_server:
            response = {"status": "error", "message": "Checksum inválido!"}
        else:
            submission_date = datetime.now()
            db_conn = get_db_connection()
            if db_conn:
                cursor = db_conn.cursor()
                try:
                    cursor.execute(
                        "INSERT INTO submissions (sender_name, file_data, file_type, submission_date) VALUES (%s, %s, %s, %s)",
                        (username, file_data, file_type, submission_date),
                    )
                    db_conn.commit()
                    response = {"status": "success", "message": "Dados enviados com sucesso!"}
                except Exception as e:
                    print(f"Erro ao salvar no banco de dados: {e}")
                    db_conn.rollback()
                    response = {"status": "error", "message": "Erro ao salvar os dados."}
                finally:
                    cursor.close()
                    db_conn.close()
            else:
                response = {"status": "error", "message": "Falha na conexão com DB."}

    
    elif action == "list_data":
        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor()
            try:
                cursor.execute(
                    "SELECT id, sender_name, file_type, submission_date FROM submissions ORDER BY submission_date DESC"
                )
                results = cursor.fetchall()
                data_list = []
                for row in results:
                    data_list.append(
                        {
                            "id": row[0],
                            "name": row[1],
                            "file_type": row[2],
                            "date": row[3].isoformat(),
                        }
                    )
                response = data_list
            except Exception as e:
                print(f"Erro ao buscar dados: {e}")
                response = {"status": "error", "message": "Erro ao buscar dados."}
            finally:
                cursor.close()
                db_conn.close()
        else:
            response = {"status": "error", "message": "Falha na conexão com DB."}

    
    elif action == "download":
        file_id = request["id"]
        db_conn = get_db_connection()
        if db_conn:
            cursor = db_conn.cursor()
            try:
                cursor.execute(
                    "SELECT sender_name, file_data, file_type FROM submissions WHERE id = %s",
                    (file_id,),
                )
                result = cursor.fetchone()
                if result:
                    sender_name, file_data, file_type = result
                    file_data_base64 = base64.b64encode(file_data).decode("utf-8")
                    checksum = calc_md5(file_data)
                    response = {
                        "status": "success",
                        "name": sender_name,
                        "file_type": file_type,
                        "file_data": file_data_base64,
                        "checksum": checksum,
                    }
                else:
                    response = {"status": "error", "message": "Arquivo não encontrado."}
            except Exception as e:
                print(f"Erro ao buscar arquivo: {e}")
                response = {"status": "error", "message": "Erro ao buscar arquivo."}
            finally:
                cursor.close()
                db_conn.close()
        else:
            response = {"status": "error", "message": "Falha na conexão com DB."}

    else:
        response = {"status": "error", "message": "Ação inválida."}

    
    if is_udp and udp_socket and addr:
        udp_socket.sendto(json.dumps(response).encode("utf-8"), addr)
    return response




def handle_client(conn, addr):
    try:
        full_data = b""
        while True:
            packet = conn.recv(4096)
            if not packet:
                break
            full_data += packet
            try:
                request = json.loads(full_data.decode("utf-8"))
                break
            except json.JSONDecodeError:
                continue

        response = process_request(request)
        conn.sendall(json.dumps(response).encode("utf-8"))
    except Exception as e:
        print(f"Erro na conexão com {addr}: {e}")
    finally:
        conn.close()

def start_tcp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
        print(f"Servidor TCP ouvindo em {HOST}:{PORT}")
        while True:
            conn, addr = s.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()




def start_udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((HOST, PORT))
        print(f"Servidor UDP ouvindo em {HOST}:{PORT}")
        while True:
            data, addr = s.recvfrom(65535)
            try:
                request = json.loads(data.decode("utf-8"))
                process_request(request, is_udp=True, addr=addr, udp_socket=s)
            except Exception as e:
                print(f"Erro ao processar requisição UDP: {e}")




if __name__ == "__main__":
    mode = input("Escolha protocolo (tcp/udp): ").strip().lower()
    if mode == "tcp":
        start_tcp()
    elif mode == "udp":
        start_udp()
    else:
        print("Protocolo inválido.")
