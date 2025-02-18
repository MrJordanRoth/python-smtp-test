import smtplib
import ssl
import socket
import tkinter as tk
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# Function to establish connection to the SMTP server
def test_smtp_server(host, port, use_tls, use_ssl, username=None, password=None, from_email="test@example.com", to_email="test@example.com"):
    connection_log = []  # Log to track commands and connections
    try:
        # Create an SMTP connection with the appropriate encryption method
        connection_log.append(f"Attempting to connect to {host}:{port}")
        if use_ssl:
            connection_log.append("Using SSL encryption")
            context = ssl.create_default_context()
            server = smtplib.SMTP_SSL(host, port, context=context)
        else:
            connection_log.append("Using plain connection")
            server = smtplib.SMTP(host, port)
            if use_tls:
                connection_log.append("Starting TLS encryption")
                server.starttls()

        # Authenticate if credentials are provided
        if username and password:
            connection_log.append(f"Logging in as {username}")
            server.login(username, password)

        # Successfully connected, now send a test email
        connection_log.append("Connection successful")
        result_message = f"Successfully connected to {host}:{port} with {'SSL' if use_ssl else 'TLS' if use_tls else 'No encryption'} encryption."

        # Create a simple test email
        subject = "SMTP Test"
        body = "This is a test e-mail."

        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        # Send email
        connection_log.append(f"Sending test email from {from_email} to {to_email}")
        server.sendmail(from_email, to_email, msg.as_string())
        result_message += f"\nTest email sent to {to_email}."

        # Close the connection to the server
        connection_log.append("Closing connection")
        server.quit()

        return result_message + "\n\nConnection Log:\n" + "\n".join(connection_log)

    except smtplib.SMTPAuthenticationError as e:
        return f"Authentication failed. Please check your credentials.\n{e}\n" + "\n".join(connection_log)
    except smtplib.SMTPException as e:
        return f"SMTP error occurred: {e}\n" + "\n".join(connection_log)
    except socket.error as e:
        return f"Socket error occurred: {e}.\n" + "\n".join(connection_log)
    except Exception as e:
        return f"An unexpected error occurred: {e}\n" + "\n".join(connection_log)

# The rest of the GUI implementation remains unchanged
# GUI to get user input and display results
def on_test_button_click():
    host = host_entry.get()
    port = port_entry.get()
    try:
        port = int(port)
    except ValueError:
        messagebox.showerror("Invalid Input", "Port must be a valid number.")
        return

    use_tls = tls_var.get()
    use_ssl = ssl_var.get()

    if use_tls and use_ssl:
        messagebox.showerror("Invalid Input", "You can't use both SSL and TLS simultaneously. Please choose one.")
        return

    authenticate = auth_var.get()
    username = username_entry.get() if authenticate else None
    password = password_entry.get() if authenticate else None

    from_email = from_email_entry.get()
    to_email = to_email_entry.get()

    if not from_email or not to_email:
        messagebox.showerror("Invalid Input", "Sender and recipient email must be provided.")
        return

    result = test_smtp_server(host, port, use_tls, use_ssl, username, password, from_email, to_email)
    result_text.config(state=tk.NORMAL)
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, result)
    result_text.config(state=tk.DISABLED)

# GUI setup remains unchanged
app = tk.Tk()
app.title("SMTP Server Tester")
app.geometry("500x500")

# GUI elements
tk.Label(app, text="SMTP Server (FQDN or IP):").grid(row=0, column=0, padx=10, pady=5, sticky="e")
host_entry = tk.Entry(app, width=40)
host_entry.grid(row=0, column=1, padx=10, pady=5)

tk.Label(app, text="Port:").grid(row=1, column=0, padx=10, pady=5, sticky="e")
port_entry = tk.Entry(app, width=40)
port_entry.grid(row=1, column=1, padx=10, pady=5)

ssl_var = tk.BooleanVar()
tls_var = tk.BooleanVar()

tk.Label(app, text="Encryption:").grid(row=2, column=0, padx=10, pady=5, sticky="e")
tk.Checkbutton(app, text="SSL", variable=ssl_var).grid(row=2, column=1, padx=10, pady=5, sticky="w")
tk.Checkbutton(app, text="TLS", variable=tls_var).grid(row=3, column=1, padx=10, pady=5, sticky="w")

auth_var = tk.BooleanVar()
tk.Label(app, text="Authentication:").grid(row=4, column=0, padx=10, pady=5, sticky="e")
tk.Checkbutton(app, text="Authenticate", variable=auth_var).grid(row=4, column=1, padx=10, pady=5, sticky="w")

username_entry = tk.Entry(app, width=40)
password_entry = tk.Entry(app, width=40, show="*")

def toggle_auth_fields():
    if auth_var.get():
        username_entry.grid(row=5, column=1, padx=10, pady=5)
        password_entry.grid(row=6, column=1, padx=10, pady=5)
    else:
        username_entry.grid_forget()
        password_entry.grid_forget()

auth_var.trace("w", lambda *args: toggle_auth_fields())

tk.Label(app, text="Sender Email:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
from_email_entry = tk.Entry(app, width=40)
from_email_entry.grid(row=7, column=1, padx=10, pady=5)

tk.Label(app, text="Recipient Email:").grid(row=8, column=0, padx=10, pady=5, sticky="e")
to_email_entry = tk.Entry(app, width=40)
to_email_entry.grid(row=8, column=1, padx=10, pady=5)

test_button = tk.Button(app, text="Test SMTP Server", command=on_test_button_click)
test_button.grid(row=9, column=0, columnspan=2, pady=10)

result_text = tk.Text(app, width=60, height=10, wrap=tk.WORD, state=tk.DISABLED)
result_text.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

app.mainloop()
