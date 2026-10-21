# CareerTrack — Job & Internship Application Tracker

CareerTrack includes a React frontend, a TypeScript/Express server, a Java/JDBC backend, and MySQL scripts.

## Project folders

- `frontend/server.ts` — TypeScript/Express web server.
- `frontend/code/` — UI source code.
- `frontend/assets/images/` — app images and AI Studio-generated images.
- `frontend/public/` — public static assets and helper files.
- `backend/` — Java application source.
- `database/` — MySQL schema, sample data, queries, and procedures.

The Node.js package manifest is in `integration/`.
`integration/` also contains the Vite/TypeScript settings and demo notes.

## Run the application

Prerequisite: Node.js.

1. Open a terminal in `integration/` and install dependencies:
   ```sh
   cd integration
   npm install
   ```
2. Create `integration/.env.local` if the application needs local environment variables.
3. Start the application:
   ```sh
   npm run dev
   ```

The development server is implemented in `frontend/server.ts`.

## Database

Run `database/schema.sql` and, if desired, `database/sample_data.sql` in MySQL. The remaining SQL scripts in `database/` provide queries, procedures, and user details setup.

See `backend/README.md` for Java backend setup and execution instructions.
