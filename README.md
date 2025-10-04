# ConnectU - Real-time Chat Application

A full-stack chat application built with React, Node.js, Express, Socket.io, and SQLite.

## Features

- User registration and authentication
- Add contacts from user list
- Real-time messaging with WebSocket
- Persistent message history
- Responsive design

## Tech Stack

**Frontend:**
- React with TypeScript
- Socket.io Client
- Axios for HTTP requests

**Backend:**
- Node.js with Express
- Socket.io for real-time communication
- SQLite database
- JWT authentication
- bcryptjs for password hashing

## Setup Instructions

### Backend Setup

1. Navigate to backend directory:
```bash
cd backend
```

2. Install dependencies:
```bash
npm install
```

3. Start the server:
```bash
npm run dev
```

The backend server will run on `http://localhost:5000`

### Frontend Setup

1. Navigate to frontend directory:
```bash
cd frontend
```

2. Install dependencies (already done during setup):
```bash
npm install
```

3. Start the React app:
```bash
npm start
```

The frontend will run on `http://localhost:3000`

## Usage

1. Register a new account or login with existing credentials
2. Add contacts by clicking the "+" button in the contacts section
3. Select a contact to start chatting
4. Messages are delivered in real-time using WebSocket connection
5. Message history is preserved and loaded when selecting contacts

## API Endpoints

- `POST /api/register` - User registration
- `POST /api/login` - User login
- `GET /api/users` - Get all users (for adding contacts)
- `POST /api/contacts` - Add a contact
- `GET /api/contacts` - Get user's contacts
- `GET /api/messages/:contactId` - Get message history with a contact

## WebSocket Events

- `join` - User joins with their ID
- `sendMessage` - Send a message to another user
- `newMessage` - Receive a new message
- `messageConfirm` - Confirm message was sent

## Database Schema

**Users Table:**
- id (Primary Key)
- username
- email
- password (hashed)

**Contacts Table:**
- id (Primary Key)
- user_id (Foreign Key)
- contact_id (Foreign Key)

**Messages Table:**
- id (Primary Key)
- sender_id (Foreign Key)
- receiver_id (Foreign Key)
- message
- timestamp