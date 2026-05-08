# AI-Assisted Nmap Automation

This project is a secure system that converts natural language scan requests into safe Nmap commands.

Instead of writing Nmap commands manually, the user can type a request in plain English, such as:

- Scan 127.0.0.1 for ports 22, 80, and 443
- Detect services running on 192.168.1.10
- Identify the operating system of a target host

The system then:
1. understands the request
2. chooses the correct scan type
3. validates the request
4. builds a safe Nmap command
5. runs the scan inside Docker
6. parses the results
7. returns a readable summary

The main goal of this project is to make Nmap easier to use while keeping the process controlled and secure.

---

## Main Features

- User registration and login
- JWT-based authentication
- Natural language scan requests
- LLM-assisted scan type selection
- Validation engine for safer command generation
- Allowlist-based target control
- Docker sandbox for Nmap execution
- XML result parsing
- Human-readable scan summary
- Audit logging

---

## Why this project was built

Nmap is a powerful network scanning tool, but it can be difficult for beginners or non-expert users to use correctly.

This project was built to help bridge that gap by allowing the user to describe what they want in plain language, while the system handles the technical command generation in a safer and more structured way.

It also adds important security controls so that unsafe or unauthorised requests can be rejected before execution.

---

## Tech Stack

This project uses:

- Python
- FastAPI
- PostgreSQL
- SQLAlchemy
- Docker
- Nmap
- JWT authentication
- XML parsing
- LLM-based request interpretation

---

## Project Structure

app/
├── __init__.py
├── config.py
├── database.py
├── docker_sandbox.py
├── gpt_service.py
├── gpt_service2.py
├── mcp_tools.py
├── models.py
├── output_parser.py
├── validation.py
└── routers/
    ├── __init__.py
    ├── audit.py
    ├── auth.py
    ├── health.py
    └── scan.py

Main parts of the system include:

- auth → handles user registration and login
- scan router → receives scan requests
- LLM/service layer → interprets natural language input
- validation engine → checks whether the request is safe
- Docker execution layer → runs Nmap in an isolated environment
- parser → reads Nmap XML output
- audit log → stores scan activity

---

## How the system works

The system follows this flow:

1. The user logs in
2. The user sends a scan request in natural language
3. The system identifies the correct scan type
4. The request is validated
5. If valid, a safe Nmap command is generated
6. The command is run inside Docker
7. The output is parsed and summarised
8. The activity is logged

If the request is unsafe, invalid, or outside the allowed scope, it is rejected before execution.

---

## Supported Scan Types

The project is designed to support controlled scan actions such as:

- Port scanning
- Service detection
- OS detection
- Host discovery
- Limited vulnerability scanning using approved scripts only

---

## Safety Controls

This project was built with security in mind.

The validation layer checks things such as:

- target allowlist
- invalid or dangerous targets
- port validity
- maximum allowed port range
- CIDR size restrictions
- blocked or unsafe scan behaviour
- allowed NSE scripts only

This means the system is not just generating commands blindly.
It checks the request before anything is executed.

---

## Requirements

Before running the project, make sure you have these installed:

- Python 3.11 or later
- Git
- Docker Desktop
- PostgreSQL
- Nmap
- A code editor such as VS Code

---

## Installation and Setup

### 1. Clone the repository

Open Command Prompt or PowerShell and run:

git clone https://github.com/YOUR_USERNAME/YOUR_REPOSITORY_NAME.git
cd YOUR_REPOSITORY_NAME

Replace:
- YOUR_USERNAME with your GitHub username
- YOUR_REPOSITORY_NAME with your repository name

---

### 2. Create a virtual environment

#### Windows
python -m venv venv

#### macOS / Linux
python3 -m venv venv

---

### 3. Activate the virtual environment

#### Windows Command Prompt
venv\Scripts\activate

#### Windows PowerShell
.\venv\Scripts\Activate.ps1

#### macOS / Linux
source venv/bin/activate

---

### 4. Install dependencies

Make sure you are inside the project folder, then run:

pip install -r requirements.txt

This installs all required Python packages from the requirements.txt file.

---

### 5. Create the environment file

Create a file named .env in the root of the project.

You can copy the contents from .env.example and update them with your own values.

Example:

OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4.1
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/nmapdb
SECRET_KEY=change-this
DOCKER_KALI_IMAGE=kalilinux/kali-rolling

---

### 6. Start PostgreSQL

Make sure PostgreSQL is running and the database in your DATABASE_URL exists.

If needed, create the database manually before running the application.

---

### 7. Start Docker Desktop

Make sure Docker Desktop is open and running.

This project uses Docker to run Nmap inside an isolated container for safer execution.

---

### 8. Run the application

Once everything is ready, run:

uvicorn app.main:app --reload

The app should start locally, usually at:

http://127.0.0.1:8000

Swagger documentation should normally be available at:

http://127.0.0.1:8000/docs

---

## Windows Notes

If you are using Windows, keep these points in mind:

- run Command Prompt, PowerShell, or VS Code terminal as needed
- Docker Desktop must be running before scan execution
- PostgreSQL service must be started
- if psql is not recognised, use the full PostgreSQL bin path or add it to PATH
- if PowerShell blocks activation, you may need to allow script execution temporarily

Example for PowerShell execution policy:

Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Then activate again:

.\venv\Scripts\Activate.ps1

---

## API Endpoints

Some main endpoints in the project are:

### Authentication
- /api/v1/auth/register
- /api/v1/auth/login

### Scan
- /api/v1/scan/allowlist
- /api/v1/scan/run

### Other
- /health

You can test these using:
- Swagger UI
- Postman
- curl

---

## Example Workflow

A normal workflow would be:

1. Register a user
2. Log in and receive a token
3. Add allowed targets to the allowlist
4. Submit a natural language scan request
5. Let the system validate and process the request
6. Review the results and summary
7. Check the audit log if needed

---

## Example Test Queries

Here are some example natural language requests.

### Accepted examples
- Scan 127.0.0.1 for ports 22, 80 and 443
- Detect services running on 127.0.0.1 on ports 22 and 80
- Identify the operating system of 127.0.0.1
- Discover live hosts on 192.168.1.0/24

### Rejected examples
- Scan 127.0.0.1 for port 99999
- Discover live hosts on 192.168.0.0/16
- Scan google.com for ports 80 and 443
- Run a denial of service NSE script against 127.0.0.1

These examples are useful for testing validation, command generation, and rejection behaviour.

---

## Repository Contents

This repository includes:

- source code
- API routes
- database models
- validation logic
- Docker configuration
- supporting project files

Sensitive files such as real .env values should not be uploaded.

---

## Limitations

This project has some limitations:

- it only supports a controlled set of scan actions
- it depends on a configured Docker and Nmap environment
- advanced scan behaviours are intentionally restricted
- vulnerability scanning is limited to approved scripts
- the quality of interpretation depends on the model and validation logic
- it is designed for authorised and controlled environments, not unrestricted internet scanning

These limitations are intentional in order to keep the system safer and more realistic for a secure prototype.

---

## Future Improvements

Possible future work includes:

- a full web-based frontend
- better visualisation of scan results
- richer reporting and export options
- improved user roles and permissions
- stronger scan scheduling and queue management
- broader but still safe scan support
- better local model integration
- live progress tracking during scans

---

## Academic Note

This project was developed as part of a master’s dissertation/project.

The purpose of the project is not only to produce working software, but also to explore how natural language interfaces can be combined with cybersecurity tools in a safer and more controlled way.

---

## Important Warning

This project is for educational and authorised use only.

Do not use it to scan systems, networks, or domains without proper permission.

The system is designed to work in controlled environments and includes restrictions for that reason.

---

## Author

Huraira Tariq
MSc AI Engineering
University of the West of Scotland
