@echo off

rem Check if python is installed
python -V >nul 2>&1
if not errorlevel 1 (
    rem Python is installed
    rem Check if virtual environment already exists
    if not exist env (
        rem Create virtual environment
        python -m venv env
    )

    rem Activate virtual environment
    call env\Scripts\activate.bat

    rem Install packages from requirements.txt
    pip install -r requirements.txt

    rem Run the project
    python manage.py runserver

    rem Open the project in Chrome
    start chrome http://127.0.0.1:8000

    rem Deactivate the virtual environment when the user closes the command prompt
    @echo off
) else (
    rem Python is not installed
    echo Python is not installed on this machine.
    echo Please download and install Python from https://www.python.org/downloads/release/python-3105/
    pause
    exit
)
