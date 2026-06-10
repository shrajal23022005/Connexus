# 🚀 Connexus – Influencer & Brand Collaboration Platform

Connexus is a full-stack web platform that connects brands with influencers for seamless collaborations, campaign management, and event bookings.

The platform allows brands to discover influencers based on category, city, and gender, while influencers can create professional profiles, manage events, and receive collaboration requests.

---

## ✨ Features

### 👤 Authentication & User Management
- User Registration & Login
- JWT-based Authentication
- Password Encryption using BCrypt
- Forgot Password via Email
- Session Persistence
- Role-Based Access Control
  - Brand
  - Influencer
  - Admin

### 🎯 Influencer Management
- Create & Update Influencer Profiles
- Upload Profile Pictures
- Social Media Links
- Category-Based Classification
- City-Based Discovery

### 🏢 Brand Features
- Brand Profile Management
- Search Influencers by:
  - Category
  - Gender
  - City
- View Detailed Influencer Profiles
- Book Influencers for Events

### 📅 Event Management
- Create Events
- Manage Event Bookings
- Delete Events
- View Booking Details

### 🛠 Admin Dashboard
- View All Users
- Block / Unblock Users
- Delete Users
- View All Influencers
- Monitor Platform Activity

### 🔒 Security Features
- JWT Authentication
- Password Hashing (BCrypt)
- Helmet Security Middleware
- Rate Limiting
- File Upload Validation
- Environment Variable Protection
- Protected Admin APIs
- Input Validation

---

## 🏗 Tech Stack

### Frontend
- HTML5
- CSS3
- Bootstrap 5
- JavaScript
- jQuery
- AngularJS

### Backend
- Node.js
- Express.js

### Database
- MySQL

### Security
- JWT
- BCrypt
- Helmet
- Express Rate Limit

### Email Services
- Nodemailer
- Gmail SMTP

---

## 📂 Project Structure

```bash
Connexus/
│
├── public/
│   ├── index.html
│   ├── client-dash.html
│   ├── client-profile.html
│   ├── infl-dash.html
│   ├── inf-profile.html
│   ├── infl-finder.html
│   ├── admin-dash.html
│   └── uploads/
│
├── server.js
├── package.json
├── .env
└── README.md
```

---

## ⚙️ Environment Variables

Create a `.env` file in the root directory:

```env
PORT=1500

DB_HOST=your_host
DB_USER=your_user
DB_PASSWORD=your_password
DB_NAME=your_database

MAIL_USER=your_email@gmail.com
MAIL_PASS=your_app_password

JWT_SECRET=your_secret_key
```

---

## 🚀 Installation & Setup

### Clone Repository

```bash
git clone https://github.com/shrajal23022005/Connexus.git
cd connexus
```

### Install Dependencies

```bash
npm install
```

### Configure Environment Variables

Create the `.env` file and add the required credentials.

### Start Server

```bash
npm start
```

Server will run on:

```bash
http://localhost:1500
```

---

## 🔐 User Roles

### Brand
- Search Influencers
- Manage Profile
- Create Bookings

### Influencer
- Manage Profile
- Manage Events
- Receive Collaboration Requests

### Admin
- Manage Users
- Manage Influencers
- Moderate Platform

---

## 📸 Screenshots

Add screenshots here after deployment.

```md
/screenshots/home.png
/screenshots/dashboard.png
/screenshots/finder.png
/screenshots/admin.png
```

---

## 🌟 Future Improvements

- Real-Time Chat
- Campaign Tracking
- Analytics Dashboard
- Payment Integration
- Notifications System
- Cloud Image Storage (Cloudinary)

---

## 👨‍💻 Author

**Shrajal Mishra**

- GitHub: https://github.com/shrajal23022005

---

## 📜 License

This project is developed for educational and portfolio purposes.