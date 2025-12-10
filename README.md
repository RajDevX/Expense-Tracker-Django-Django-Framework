# Expense Tracker Using Django + REST Framework APIs

![Homepage](diems/images/homepage.png)

## Objective
To develop a secure, scalable expense tracker with complete CRUD operations for managing users, categories, transactions, budgets, and monthly limits.

## Technologies Used
- HTML  
- CSS  
- JavaScript  
- Django  
- Django REST Framework  
- MySQL  

## Description
This project is a secure and scalable expense-tracking system built with Django and Django REST Framework. It provides full API-based CRUD control for:

- Users  
- Categories  
- Transactions  
- Budgets 

The system can efficiently manage expenses and trigger alerts when the monthly budget limit is reached.

## Screenshots

### Authentication
![Login Page](diems/images/login.png)  
![Signup Page](diems/images/siginup.png)

### Admin Pages
![Admin Page](diems/images/adminpage.png)  
![Admin Page 2](diems/images/adminpage2.png)

### Homepage
![Homepage](diems/images/homepage.png)  
![Homepage 2](diems/images/homepage2.png)  
![Homepage 3](diems/images/homepage3.png)


## Features
- User authentication (signup/login/logout)  
- Full CRUD operations. 
- Budget tracking and alerts when limits are exceeded  
- Category-wise expense management  
- Admin dashboard for management  

## Installation & Setup

1. Clone the repository:  
```bash
git clone https://github.com/RajDevX/Expense-Tracker-Django-Django-REST-Framework.git
```
## Installation & Setup

Follow these steps to get the project running locally:

### 1. Navigate to the project directory
```bash
cd Daily-expensive-management-system-main
```
2. Create a virtual environment
```bash
python -m venv venv
```
3. Activate the virtual environment

Windows:
```bash
venv\Scripts\activate
```
Linux/macOS:
```bash
source venv/bin/activate
```
4. Install dependencies

5. Apply database migrations
```bash
  python manage.py makemigrations
  python manage.py migrate
```
6. Run the development server
   ```bash
   python manage.py runserver

7.Open your browser and navigate to:
  ```bash
  http://127.0.0.1:8000

