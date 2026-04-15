# DepShield: AI Dependency Risk Analyzer

DepShield is a personal AI-powered tool designed to analyze project dependencies for security risks and vulnerabilities. It provides a clean dashboard to visualize and manage your software supply chain security.

## Features

- **AI-Driven Risk Analysis**: Automatically identifies potential risks in your dependencies.
- **Dependency Visualization**: See exactly what's in your project at a glance.
- **Fast and Lightweight**: Built with React and Vite for a seamless developer experience.

## Getting Started

Follow these steps to set up and run DepShield on your local machine.

### Prerequisites

- **Node.js**: v18 or higher ([Download](https://nodejs.org/))
- **Python**: v3.8 or higher ([Download](https://www.python.org/))
- **Git**: Installed and available in your PATH

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/DepShield.git
   cd DepShield
   ```

2. **Install Frontend Dependencies**:
   ```bash
   npm install
   ```

3. **Install Backend Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

### Running the Application

DepShield requires both the React frontend and the Flask backend to be running.

#### 1. Start Both Simultaneously (Recommended)
Run the following command in the root directory:
```bash
npm start
```
This uses `concurrently` to launch the Vite development server and the Python Flask API at the same time.

#### 2. Manual Startup (Separate Terminals)
If you prefer to run them separately:

- **Frontend**:
  ```bash
  npm run dev
  ```
  App available at `http://localhost:5173`.

- **Backend**:
  ```bash
  npm run backend
  ```
  API available at `http://localhost:5000`.

### Building for Production

To create a production-ready bundle of the frontend:
```bash
npm run build
```

---


