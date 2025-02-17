import smtplib
import ssl
import socket
import tkinter as tk
from tkinter import messagebox
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import base64
import requests
from msal import ConfidentialClientApplication


# Function to acquire OAuth2 token for Modern Auth
def get_oauth2_token(tenant_id, client_id, client_secret, scope):
    app = ConfidentialClientApplication(
        client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
        client_credential=client_secret
    )
    result = app.acquire_token_for_client(scopes=[scope])
    if "access_token" in result:
        return result["access_token"]
    else:
        raise Exception(f"Could not obtain access token: {result}")


# Function to establish connection to the SMTP server
def test_smtp_server(host, port, use_tls, use_ssl, use_modern_auth=False, tenant_id=None, client_id=None,
                     client_secret=None, scope=None, username=None, password=None, from_email="test@example.com",
                     to_email="test@example.com"):
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

        # Modern Authentication (OAuth 2.0)
        if use_modern_auth:
            connection_log.append("Using Modern Authentication (OAuth 2.0)")
            if not (tenant_id and client_id and client_secret and scope):
                raise ValueError("Tenant ID, Client ID, Client Secret, and Scope are required for Modern Auth")
            token = get_oauth2_token(tenant_id, client_id, client_secret, scope)
            auth_string = base64.b64encode(f"user={username}\u0001auth=Bearer {token}\u0001\u0001".encode()).decode()
            server.docmd("AUTH", "XOAUTH2 " + auth_string)

        # If authentication is required with SMTP Auth
        elif username and password:
            connection_log.append(f"Logging in as {username}")
            server.login(username, password)

        # Successfully connected, now send a test email
        connection_log.append("Connection successful")
        result_message = f"Successfully connected to {host}:{port} with {'SSL' if use_ssl else 'TLS' if use_tls else 'No encryption'} encryption."

        # Create a simple test email
        subject = "SMTP Test"
        body = "This is a test email sent from the SMTP test script."

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
        connection_log.append(f"Authentication failed: {e.smtp_code} {e.smtp_error}")
        return f"Authentication failed. Please check your credentials.\n{e.smtp_code} {e.smtp_error}\n" + "\n".join(
            connection_log)
    except smtplib.SMTPConnectError as e:
        connection_log.append(f"Failed to connect: {e.smtp_code} {e.smtp_error}")
        return f"Failed to connect to the SMTP server {host} on port {port}.\n{e.smtp_code} {e.smtp_error}\n" + "\n".join(
            connection_log)
    except smtplib.SMTPResponseException as e:
        connection_log.append(f"SMTP response exception: {e.smtp_code} {e.smtp_error}")
        return f"SMTP error {e.smtp_code}: {e.smtp_error}\n" + "\n".join(connection_log)
    except smtplib.SMTPException as e:
        connection_log.append(f"SMTP exception occurred: {e}")
        return f"SMTP error occurred: {e}\n" + "\n".join(connection_log)
    except socket.gaierror as e:
        connection_log.append(f"DNS resolution failed: {e}")
        return f"DNS resolution failed for {host}. Check the server name or IP address.\n{e}\n" + "\n".join(
            connection_log)
    except socket.timeout as e:
        connection_log.append(f"Connection timed out: {e}")
        return f"Connection to {host}:{port} timed out. The server might be unreachable.\n{e}\n" + "\n".join(
            connection_log)
    except socket.error as e:
        connection_log.append(f"Socket error: {e}")
        return f"Socket error occurred: {e}. This could be due to network issues or server unavailability.\n" + "\n".join(
            connection_log)
    except Exception as e:
        connection_log.append(f"Unexpected error: {e}")
        return f"An unexpected error occurred: {e}\n" + "\n".join(connection_log)

    except smtplib.SMTPAuthenticationError as e:
        connection_log.append(f"Authentication failed: {e.smtp_code} {e.smtp_error}")
        return f"Authentication failed. Please check your credentials.\n{e.smtp_code} {e.smtp_error}\n" + "\n".join(connection_log)
    except smtplib.SMTPConnectError as e:
        connection_log.append(f"Failed to connect: {e.smtp_code} {e.smtp_error}")
        return f"Failed to connect to the SMTP server {host} on port {port}.\n{e.smtp_code} {e.smtp_error}\n" + "\n".join(connection_log)
    except smtplib.SMTPResponseException as e:
        connection_log.append(f"SMTP response exception: {e.smtp_code} {e.smtp_error}")
        return f"SMTP error {e.smtp_code}: {e.smtp_error}\n" + "\n".join(connection_log)
    except smtplib.SMTPException as e:
        connection_log.append(f"SMTP exception occurred: {e}")
        return f"SMTP error occurred: {e}\n" + "\n".join(connection_log)
    except socket.gaierror as e:
        connection_log.append(f"DNS resolution failed: {e}")
        return f"DNS resolution failed for {host}. Check the server name or IP address.\n{e}\n" + "\n".join(connection_log)
    except socket.timeout as e:
        connection_log.append(f"Connection timed out: {e}")
        return f"Connection to {host}:{port} timed out. The server might be unreachable.\n{e}\n" + "\n".join(connection_log)
    except socket.error as e:
        connection_log.append(f"Socket error: {e}")
        return f"Socket error occurred: {e}. This could be due to network issues or server unavailability.\n" + "\n".join(connection_log)
    except Exception as e:
        connection_log.append(f"Unexpected error: {e}")
        return f"An unexpected error occurred: {e}\n" + "\n".join(connection_log)

    except smtplib.SMTPAuthenticationError:
        connection_log.append("Authentication failed")
        return "Authentication failed. Please check your credentials.\n" + "\n".join(connection_log)
    except smtplib.SMTPConnectError:
        connection_log.append("Failed to connect to the server")
        return f"Failed to connect to the SMTP server {host} on port {port}.\n" + "\n".join(connection_log)
    except smtplib.SMTPException as e:
        connection_log.append(f"SMTP exception occurred: {e}")
        return f"SMTP error occurred: {e}\n" + "\n".join(connection_log)
    except socket.gaierror:
        connection_log.append("DNS resolution failed")
        return f"DNS resolution failed for {host}. Check the server name or IP address.\n" + "\n".join(connection_log)
    except socket.timeout:
        connection_log.append("Connection timed out")
        return f"Connection to {host}:{port} timed out. The server might be unreachable.\n" + "\n".join(connection_log)
    except socket.error as e:
        connection_log.append(f"Socket error: {e}")
        return f"Socket error occurred: {e}. This could be due to network issues or server unavailability.\n" + "\n".join(connection_log)
    except Exception as e:
        connection_log.append(f"Unexpected error: {e}")
        return f"An unexpected error occurred: {e}\n" + "\n".join(connection_log)


# GUI to get user input and display results
def on_test_button_click():
    host = host_entry.get()
    port = port_entry.get()
    try:
        port = int(port)  # Validate port is an integer
    except ValueError:
        messagebox.showerror("Invalid Input", "Port must be a valid number.")
        return

    use_tls = tls_var.get()
    use_ssl = ssl_var.get()

    if use_tls and use_ssl:
        messagebox.showerror("Invalid Input", "You can't use both SSL and TLS simultaneously. Please choose one.")
        return

    authenticate = auth_var.get()

    username = None
    password = None
    if authenticate:
        username = username_entry.get()
        password = password_entry.get()

    from_email = from_email_entry.get()
    to_email = to_email_entry.get()

    if not from_email or not to_email:
        messagebox.showerror("Invalid Input", "Sender and recipient email must be provided.")
        return

    result = test_smtp_server(host, port, use_tls, use_ssl, username, password, from_email, to_email)
    result_text.config(state=tk.NORMAL)  # Enable text widget to update it
    result_text.delete(1.0, tk.END)  # Clear the previous content
    result_text.insert(tk.END, result)  # Insert the new result
    result_text.config(state=tk.DISABLED)  # Disable text widget again


# Create the main application window
app = tk.Tk()
app.title("SMTP Server Tester")
app.geometry("500x500")  # Set window size

# Create labels, entries, and checkboxes for user input
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

# Only show username and password fields if authentication is enabled
def toggle_auth_fields():
    if auth_var.get():
        username_entry.grid(row=5, column=1, padx=10, pady=5)
        password_entry.grid(row=6, column=1, padx=10, pady=5)
        tk.Label(app, text="Username:").grid(row=5, column=0, padx=10, pady=5, sticky="e")
        tk.Label(app, text="Password:").grid(row=6, column=0, padx=10, pady=5, sticky="e")
    else:
        username_entry.grid_forget()
        password_entry.grid_forget()
        for widget in app.grid_slaves():
            if widget.grid_info()['row'] in ['5', '6']:
                widget.grid_forget()

auth_var.trace("w", lambda *args: toggle_auth_fields())

# Add fields for sender and recipient email
tk.Label(app, text="Sender Email:").grid(row=7, column=0, padx=10, pady=5, sticky="e")
from_email_entry = tk.Entry(app, width=40)
from_email_entry.grid(row=7, column=1, padx=10, pady=5)

tk.Label(app, text="Recipient Email:").grid(row=8, column=0, padx=10, pady=5, sticky="e")
to_email_entry = tk.Entry(app, width=40)
to_email_entry.grid(row=8, column=1, padx=10, pady=5)

# Create the "Test" button to run the test
test_button = tk.Button(app, text="Test SMTP Server", command=on_test_button_click)
test_button.grid(row=9, column=0, columnspan=2, pady=10)

# Create a text widget to display results
result_text = tk.Text(app, width=60, height=10, wrap=tk.WORD, state=tk.DISABLED)
result_text.grid(row=10, column=0, columnspan=2, padx=10, pady=5)

# Run the application
app.mainloop()
