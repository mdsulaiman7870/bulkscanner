
<h1 align="center">
  <br>
  <a href=""><img src="https://github.com/Salman7870/bulkscanner/blob/b324771cc72abe95a7f7421b42964f17247434c9/static/logo.png" alt="Markdownify" width="200"></a>
  <br>
  BulkScanner
  <br>
</h1>

<h4 align="center">A tool for SOC Analysts to analyze observables in bulk.</h4>

<p align="center">
  <a href="#">
    <img src="https://badge.fury.io/py/django.svg"
         alt="Gitter">
  </a>
  <a href="https://saythanks.io/to/muhammadsulaiman7870">
      <img src="https://img.shields.io/badge/SayThanks.io-%E2%98%BC-1EAEDB.svg">
  </a>
</p>

<p align="center">
  <a href="#introduction">Introduction</a> •
  <a href="#key-features">Key Features</a> •
  <a href="#download-and-installation">Download and Installation</a> •
  <a href="#default-credentials">Default Credentials</a> •
  <a href="#how-to-use">How To Use</a> •
  <a href="#currently-integrated-tools">Currently Integrated Tools</a> •
  <a href="#about-secret-key">About secret_key.yaml file</a> •
  <a href="#technology-used-in-this-project">Technology used in this project</a> •
  <a href="#license">License</a>
</p>

# Introduction
BulkScanner is a web based tool designed and developed for a security/SOC analysts to analyze observables in bulk such as IP addresses, hashes, urls, and domains. BulkScanner is based on open-source intelligence analyzers such as VirusTotal, AbuseIPDB, X-Force Exchange(IBM), metadefender etc. 


# Key Features

* Analyze observables in bulk
* Accept large log file (CSV only)
* Custom Column names
* Adding API keys for each tool
* Store each analyzed observable in database
* First check for observable in the database before making request to the selected tool.
    - If observable present in database, will not send request
    - If observable not present in database, will send request for analyzing. We can save our time and API calls by doing this.
* Create a unique group of selected obserables before analyzing. Remove the duplicated objects and save API calls by doing this.
* Ignore Private IP addresses.
* Store failed observable in a seperate table so we can save the API calls by sending the requests of failed observables again and again. (Observables that have no records are considered failed objects.)
* The location information for IP addresses is obtained using a tool specifically designed for identifying geographical locations, called <b>geolocation-db.com</b>.
* The Observable Details page to generate concise and precise reports.
* Admin panel for admin actions.

# Download and Installation

You can download the latest version of BulkScanner by clicking [download](https://github.com/Salman7870/bulkscanner/archive/refs/heads/main.zip), or click on <b>Code > Download Zip</b>. Or you may clone the repository "https://github.com/Salman7870/bulkscanner.git"


## Pre-requisites for BulkScanner
- Python 3.10.5 or above must be installed

## Easy Install
This installation process is designed for non-techincal users.

### Step 1
Download the zip file by clicking [download](https://github.com/Salman7870/bulkscanner/archive/refs/heads/main.zip) and extract it.

### Step 2
Execute or run the bat file <b>"run.bat"</b> inside the project directory and that's it. Wait sometime, after completion, visit to http://127.0.0.1:8000.

What happens when click on run.bat?
- It will first check if python is installed or not on your machine.
- if python is installed, then the script will automatically create a virtual enivroment for you and install all the required packages to run the project. After installation, you will see the django server is running on your CMD console. Just go to browser and run http://127.0.0.1:8000
- If Python is not installed, a message will display on the console "Python is not installed on this machine."
- Finally, it will deactivate the virtual environment if user closes the CMD console or Terminal.
> **Note**
> This installation is for windows operating systems only. To run and install BulkScanner on Linux based machines, refer to **Technical Install** guide below.

## Technical Install

### Step 1
Download or clone the repository.

### Step 2
Create a virtual environment by running <code>python -m venv venv</code> in the project directory and activate it by <code>venv\Scripts\activate</code>

### Step 3
Install all the required packages by running <code>pip install -r requirements.txt</code>

### Step 4

Run the django server by <code>python manage.py runserver</code> and access the app by http://127.0.0.1:8000

## Database Configuration
By default, SQLite database is used in this project. You use various databases. Below are the supported databases in Django.
- PostgreSQL
- MariaDB
- MySQL
- Oracle
- SQLite
> **Note**
> : SQLite database may be slow in performance when number of records increases and not recommended for large data.

# Default Credentials
Username: admin

Email: admin@admin.com

Password: admin

Make sure to change default password for the user. You can also create your own super user by <code>python manage.py createsuperuser </code>

Or to create a normal user, just visit http://127.0.0.1:8000/accounts/register to register a new user.

# How To Use

## Add  API Keys 
First of all, add API keys of the tools which you want to use such as VirusTotal and AbuseIPDB.
![Add API keys](https://github.com/Salman7870/bulkscanner/blob/b324771cc72abe95a7f7421b42964f17247434c9/static/img/docs-images/add-api-keys.png)

You can add multiple API keys and can be recoganize by Owner Email or Name.

## Add Column names
Columns are the keys in log files such as source_ip, destination_ip, md5_hash, etc..

Suppose the below CSV log file. Here, we will add **source_ip** and **destination_ip** column names so we can select it when analyzing or scanning this file.
![Add Column names](https://github.com/Salman7870/bulkscanner/blob/4af0492466e2bf82a24dec524a8ccc87f047f328/static/img/docs-images/log-sample.png)
To do this, click on **Add Columns** and enter the column name.
![Add Column names](https://github.com/Salman7870/bulkscanner/blob/4af0492466e2bf82a24dec524a8ccc87f047f328/static/img/docs-images/add-api-keys.png)


## Scan a file

Now you are ready to go. Select your desire tool under **Tools**, then select API key, column name and upload your CSV log file. Click on **Scan Now** button.
![Scan a file](https://github.com/Salman7870/bulkscanner/blob/b324771cc72abe95a7f7421b42964f17247434c9/static/img/docs-images/scan-file.png)

# Currently Integrated Tools

Currently, Following tools/analyzers have been integrated:

- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

[GeoLocation-DB](https://geolocation-db.com) tool is used to get location information

# About secret_key yaml file
Django **SECRET_KEY** is a randomly generated string of characters that is used to provide cryptographic signing for various security-related features in Django framework, such as authentication, sessions, and CSRF (Cross-Site Request Forgery) protection.

The SECRET_KEY should be kept secret and not shared with anyone, as it is used to generate secure hashes and tokens that are used to authenticate users and protect against attacks.

It is placed in **settings.py** file as SECRET_KEY = "random_string"

To address the issue of avoiding the sharing of SECRET_KEY, I have added a peace of code the **settings.py** file to assign a unique SECRET_KEY to each user during their initial installation.

Once the application is run for the first time, the code in **settings.py** checks for the presence of a SECRET_KEY in the **secret_key.yaml** file. If a key exists, it is retrieved from the file. However, if it does not exist, a new, robust secret key is generated and automatically stored in the **secret_key.yaml** file. This ensures that every user who downloads this project has their own individual and exclusive SECRET_KEY for their usage of the application. 

Now everytime, when a user run the application, it will use the secret key store in the secret_key.yaml file.


## Support

<a href="https://www.buymeacoffee.com/mdsulaiman" target="_blank"><img src="https://www.buymeacoffee.com/assets/img/custom_images/purple_img.png" alt="Buy Me A Coffee" style="height: 41px !important;width: 174px !important;box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;-webkit-box-shadow: 0px 3px 2px 0px rgba(190, 190, 190, 0.5) !important;" ></a>


# Technology used in this project
- Python
- Django
- HTML
- CSS
- JavaScript

# Credits

 - [Tabler](https://tabler.io/) template is used. 
- [VirusTotal](https://www.virustotal.com/)
- [AbuseIPDB](https://www.abuseipdb.com/)

## License

MIT

---
> GitHub [@Salman7870](https://github.com/Salman7870/) &nbsp;&middot;&nbsp;
> LinkedIn [@muhammad-sulaiman7870](https://www.linkedin.com/in/muhammad-sulaiman7870/)

