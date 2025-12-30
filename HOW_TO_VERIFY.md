# How to Verify Supabase Migration

## Local Development (Filesystem Fallback)

1. **Start the server:**
   ```bash
   cd Backend
   npm install  # Install @supabase/supabase-js
   node index.js
   ```

2. **Check logs for:**
   - `clients_store_backend_selected` event with `storeType: "filesystem"` (if SUPABASE_URL not set)
   - `client_registry_initialized` with `storeType: "filesystem"`

3. **Verify admin UI:**
   - Visit `http://localhost:PORT/admin/login`
   - Login with ADMIN_EMAIL / ADMIN_PASSWORD
   - Go to `/admin/clients`
   - Should show "Config storage: <filesystem path>" message
   - Create a test client
   - Edit client config and save
   - Should show success message

4. **Verify widget endpoint:**
   - Visit `http://localhost:PORT/widget-config?client=Advantum`
   - Should return JSON config
   - Check logs for `widget_config_served` with `source: "filesystem"`

## Render Production (Supabase)

1. **Set environment variables in Render:**
   - `SUPABASE_URL` - Your Supabase project URL
   - `SUPABASE_SERVICE_ROLE_KEY` - Service role key (server-only, never expose to frontend)

2. **Deploy and check logs:**
   - Look for `clients_store_backend_selected` event with `storeType: "supabase"`
   - Look for `client_registry_initialized` with `storeType: "supabase"`

3. **Verify admin UI:**
   - Visit `https://your-app.onrender.com/admin/login`
   - Login and go to `/admin/clients`
   - Should show "Config storage: Supabase" message
   - Create a test client (should write to Supabase)
   - Edit client config and save
   - Verify in Supabase dashboard: `SELECT * FROM public.clients;`

4. **Verify widget endpoint:**
   - Visit `https://your-app.onrender.com/widget-config?client=Advantum`
   - Should return JSON config
   - Check logs for `widget_config_served` with `source: "supabase"`

5. **Verify Advantum row:**
   - First, ensure `Advantum` exists in Supabase `public.clients` table:
     ```sql
     INSERT INTO public.clients (client_id, config) 
     VALUES ('Advantum', '{"widget": {"title": "Test"}}'::jsonb)
     ON CONFLICT (client_id) DO NOTHING;
     ```
   - Visit `/admin/clients/Advantum` - should load config
   - Edit and save - should update `updated_at` and `updated_by` columns

## Troubleshooting

- **"clientsStore is not defined" error:** Fixed - all files now import from `clientsStoreAdapter`
- **Server won't start:** Check that `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` are set (or not set, for filesystem fallback)
- **404 on client config:** Verify client_id exists in Supabase table or filesystem directory
- **CSRF errors:** Normal - GET routes don't require CSRF; POST routes do (unchanged)

