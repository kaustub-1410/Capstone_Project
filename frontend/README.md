# AMCDS Dashboard

React frontend for the AMCDS simulation platform. Requires the FastAPI backend on port 8000.

```bash
npm install
npm run dev
```

Build for production:

```bash
npm run build
```

For deployment, set `VITE_API_BASE_URL` to the public base URL of the FastAPI backend
before building the frontend (for example, `https://api.example.com`). If the frontend
and backend share an origin behind a proxy, this variable can be omitted. The backend
must be deployed separately and expose `/api` routes; the local development fallback
is not used in production.
