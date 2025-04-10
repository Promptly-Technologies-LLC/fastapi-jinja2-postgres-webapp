# deploy.py
import modal

# Define the base image
image = (
    modal.Image.debian_slim(python_version="3.13")
    .apt_install("libpq-dev", "libwebp-dev")
    .pip_install_from_pyproject("pyproject.toml")
    .add_local_python_source("main")
    .add_local_python_source("routers")
    .add_local_python_source("utils")
    .add_local_python_source("exceptions")
    .add_local_dir("static", remote_path="/root/static")
    .add_local_dir("templates", remote_path="/root/templates")
)

# Define the Modal App
app = modal.App(
    name="fastapi-jinja2-postgres-webapp",
    image=image,
    secrets=[modal.Secret.from_name("fastapi-jinja2-postgres-webapp")]
)


# Define the ASGI app function
@app.function()
@modal.asgi_app()
def fastapi_app():
    from main import app as web_app

    return web_app