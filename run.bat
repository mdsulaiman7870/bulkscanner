@echo off

rem Activate the virtual environment
call venv\Scripts\activate.bat

rem Check if packages are already installed
pip freeze >> installed_packages.txt

rem Install packages from requirements.txt if not already installed
for /f "tokens=1*" %%a in (requirements.txt) do (
  findstr /x /c:"%%a" installed_packages.txt > nul || (
    echo Installing %%a
    pip install %%a
  )
)

rem Run Django project
python manage.py runserver

rem Open project in Chrome
start chrome http://127.0.0.1:8000/
