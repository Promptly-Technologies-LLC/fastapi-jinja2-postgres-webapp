---
title: "Deployment"
---

This application requires two services to be deployed and connected to each other:

1. A PostgreSQL database (the storage layer)
2. A FastAPI app (the application layer)

There are *many* hosting options available for each of these services; this guide will cover only a few of them.

## Deploying and Configuring the PostgreSQL Database

### On Digital Ocean

#### Getting Started

- Create a [DigitalOcean](mdc:https:/www.digitalocean.com) account
- Install the [`doctl` CLI tool](mdc:https:/docs.digitalocean.com/reference/doctl) and authenticate with `doctl auth init`
- Install the [`psql` client](mdc:https:/www.postgresql.org/download)

#### Create a Project

Create a new project to organize your resources:

```bash
# List existing projects
doctl projects list

# Create a new project
doctl projects create --name "YOUR-PROJECT-NAME" --purpose "YOUR-PROJECT-PURPOSE" --environment "Production"
```

#### Set Up a Managed PostgreSQL Database

Create a managed, serverless PostgreSQL database instance:

```bash
doctl databases create your-db-name --engine pg --version 17 --size db-s-1vcpu-1gb --num-nodes 1 --wait
```

Get the database ID from the output of the create command and use it to retrieve the database connection details:

```bash
# Get the database connection details
doctl databases connection "your-database-id" --format Host,Port,User,Password,Database
```

Store these details securely in a `.env.production` file (you will need to set them later in application deployment as production secrets):

```bash
# Database connection parameters
DB_HOST=your-host
DB_PORT=your-port
DB_USER=your-user
DB_PASS=your-password
DB_NAME=your-database
```

You may also want to save your database id, although you can always find it again later by listing your databases with `doctl databases list`.

#### Setting Up a Firewall Rule (after Deploying Your Application Layer)

Note that by default your database is publicly accessible from the Internet, so you should create a firewall rule to restrict access to only your application's IP address once you have deployed the application. The command to do this is:

```bash
doctl databases firewalls append <database-cluster-id> --rule <type>:<value>
```

where `<type>` is `ip_addr` and `<value>` is the IP address of the application server. See the [DigitalOcean documentation](https://docs.digitalocean.com/reference/doctl/reference/databases/firewalls/append/) for more details.

**Note:** You can only complete this step after you have deployed your application layer and obtained a static IP address for the application server.

## Deploying and Configuring the FastAPI App

### On Modal.com

The big advantages of deploying on Modal.com are:
1. that they offer $30/month of free credits for each user, plus generous additional free credit allotments for startups and researchers, and
2. that it's a very user-friendly platform.

The disadvantages are:
1. that Modal is a Python-only platform and cannot run the database layer, so you'll have to deploy that somewhere else,
2. that you'll need to make some modest changes to the codebase to get it to work on Modal, and
3. that Modal offers a [static IP address for the application server](https://modal.com/docs/guide/proxy-ips) only if you pay for a higher-tier plan starting at $250/year, which makes securing the database layer with a firewall rule cost prohibitive.

#### Getting Started

- [Sign up for a Modal.com account](https://modal.com/signup)
- Install modal in the project directory with `uv add modal`
- Run `uv run modal setup` to authenticate with Modal

#### Defining the Modal Image and App

Create a new Python file in the root of your project, for example, `deploy.py`. This file will define the Modal Image and the ASGI app deployment.

1.  **Define the Modal Image in `deploy.py`:**
    - Use `modal.Image` to define the container environment. Chain methods to install dependencies and add code/files.
    - Start with a Debian base image matching your Python version (e.g., 3.13).
    - Install necessary system packages (`libpq-dev` for `psycopg2`, `libwebp-dev` for Pillow WebP support).
    - Install Python dependencies using `run_commands` with `uv`.
    - Add your local Python modules (`routers`, `utils`, `exceptions`) using `add_local_python_source`.
    - Add the `static` and `templates` directories using `add_local_dir`. The default behaviour (copying on container startup) is usually fine for development, but consider `copy=True` for production stability if these files are large or rarely change.

    ```python
    # deploy.py
    import modal
    import os

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
        name="your-app-name",
        image=image,
        secrets=[modal.Secret.from_name("your-app-name-secret")]
    )
    ```

2.  **Define the ASGI App Function in `deploy.py`:**
    - Create a function decorated with `@app.function()` and `@modal.asgi_app()`.
    - Inside this function, import your FastAPI application instance from `main.py`.
    - Return the FastAPI app instance.
    - Use `@modal.concurrent()` to allow the container to handle multiple requests concurrently.

    ```python
    # deploy.py (continued)

    # Define the ASGI app function
    @app.function(
        allow_concurrent_inputs=100 # Adjust concurrency as needed
    )
    @modal.asgi_app()
    def fastapi_app():
        # Important: Import the app *inside* the function
        # This ensures it runs within the Modal container environment
        # and has access to the installed packages and secrets.
        # It also ensures the lifespan function (db setup) runs correctly
        # with the environment variables provided by the Modal Secret.
        from main import app as web_app

        return web_app
    ```

For more information on Modal FastAPI images and applications, see [this guide](https://modal.com/docs/guide/webhooks#how-do-web-endpoints-run-in-the-cloud).

#### Deploying the App

From your terminal, in the root directory of your project, run:

```bash
modal deploy deploy.py
```

Modal will build the image (if it hasn't been built before or if dependencies changed) and deploy the ASGI app. It will output a public URL (e.g., `https://your-username--your-app-name.modal.run`).

#### Setting Up Modal Secrets

The application relies on environment variables stored in `.env` (like `SECRET_KEY`, `DB_USER`, `DB_PASSWORD`, `DB_HOST`, `DB_PORT`, `DB_NAME`, `RESEND_API_KEY`, `BASE_URL`). These sensitive values should be stored securely using Modal Secrets.

Create a Modal Secret either through the Modal UI or CLI. Note that the name of the secret has to match the secret name you used in the `deploy.py` file, above (e.g., `your-app-name-secret`).

```bash
# Example using CLI
modal secret create your-app-name-secret \
    SECRET_KEY='your_actual_secret_key' \
    DB_USER='your_db_user' \
    DB_PASSWORD='your_db_password' \
    DB_HOST='your_external_db_host' \
    DB_PORT='your_db_port' \
    DB_NAME='your_db_name' \
    RESEND_API_KEY='your_resend_api_key' \
    BASE_URL='https://your-username--your-app-name-serve.modal.run'
```

**Important:** Ensure `DB_HOST` points to your *cloud* database host address, not `localhost` or `host.docker.internal`.

#### Testing the Deployment

Access the provided Modal URL in your browser. Browse the site and test the registration and password reset features to ensure database and Resend connections work.