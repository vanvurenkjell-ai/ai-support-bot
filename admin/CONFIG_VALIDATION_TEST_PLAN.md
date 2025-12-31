# Config Validation Test Plan

## Overview
This document outlines test scenarios for the strict config update validation system.

## Test Scenarios

### 1. Valid Update - Should Succeed
- **Action**: Update allowed fields (e.g., widget.title, colors.primary)
- **Expected**: 200 OK, config persists to Supabase, widget reflects changes immediately
- **Verify**: Check Supabase `public.clients` table and `/widget-config?clientId=...` endpoint

### 2. Invalid URL - Should Reject
- **Action**: Set `logoUrl` or `support.contactUrl` to invalid value (e.g., "not-a-url", "ftp://example.com")
- **Expected**: 400 Bad Request with error message about invalid URL
- **Verify**: Error message mentions "must be a valid HTTP or HTTPS URL"

### 3. Oversized Text Field - Should Reject
- **Action**: Set `widget.greeting` to > 300 characters
- **Expected**: 400 Bad Request with error about exceeding maximum length
- **Verify**: Error message shows field name and max length

### 4. Invalid Hex Color - Should Reject
- **Action**: Set `colors.primary` to invalid color (e.g., "red", "rgb(255,0,0)", "not-a-color")
- **Expected**: 400 Bad Request with error about invalid hex color
- **Verify**: Error message mentions "Must be a valid hex color (#RGB or #RRGGBB)"

### 5. Unknown Key Injection - Should Reject (Security)
- **Action**: Attempt to update disallowed field (e.g., `systemPrompt`, `model`, `shopifyApiKey`, `apiKey`)
- **Expected**: 400 Bad Request with error "Disallowed field: [fieldName]"
- **Verify**: Disallowed field is NOT added to config, error is logged

### 6. Client-Admin Restriction - Should Enforce Same Rules
- **Action**: As client_admin, attempt to update allowed fields + inject disallowed fields
- **Expected**: 400 Bad Request, same validation as super_admin
- **Verify**: Both roles use same allowlist (same validation rules)

### 7. Super-Admin Behavior - Should Remain Unchanged
- **Action**: As super_admin, update allowed fields
- **Expected**: 200 OK, works as before
- **Verify**: No regression in super-admin functionality

### 8. Empty Required Fields - Should Handle Gracefully
- **Action**: Clear optional fields (e.g., set `logoUrl` to empty string)
- **Expected**: 200 OK, field set to `null` in config
- **Verify**: Empty strings for optional fields are normalized to `null`

### 9. Secondary Buttons Array - Should Validate
- **Action**: Add 3+ secondary buttons, or button with invalid URL
- **Expected**: 400 Bad Request or max 2 buttons enforced
- **Verify**: Only valid buttons with valid URLs are saved

### 10. Email Validation - Should Reject Invalid
- **Action**: Set `support.email` to invalid email (e.g., "not-an-email", "missing@domain")
- **Expected**: 400 Bad Request with email validation error
- **Verify**: Error message mentions valid email format

## Manual Testing Steps

1. **Login as client_admin or super_admin**
2. **Navigate to `/admin/clients/[clientId]`**
3. **Make changes and submit form**
4. **Verify validation errors appear inline (if any)**
5. **Check server logs for `admin_client_update_validation_failed` events**
6. **Verify config persisted in Supabase**
7. **Test widget endpoint `/widget-config?clientId=[clientId]` reflects changes**

## API Testing (JSON)

Use curl or Postman to test `/admin/api/clients/:clientId` POST endpoint:

```bash
# Valid update
curl -X POST https://your-domain.com/admin/api/clients/TestClient \
  -H "Cookie: connect.sid=..." \
  -H "X-CSRF-Token: ..." \
  -H "Content-Type: application/json" \
  -d '{"widget": {"title": "New Title"}}'

# Invalid update (should fail)
curl -X POST https://your-domain.com/admin/api/clients/TestClient \
  -H "Cookie: connect.sid=..." \
  -H "X-CSRF-Token: ..." \
  -H "Content-Type: application/json" \
  -d '{"systemPrompt": "hack attempt", "widget": {"title": "Valid"}}'
```

Expected response for invalid:
```json
{
  "ok": false,
  "error": "Validation failed",
  "errors": ["Disallowed field: systemPrompt"],
  "fieldErrors": {
    "systemPrompt": "This field cannot be updated"
  }
}
```

## Security Verification

- ✅ Unknown keys are rejected (fail-closed)
- ✅ Disallowed keys are logged but not stored
- ✅ All validation happens server-side
- ✅ Client-admin and super-admin use same allowlist
- ✅ URLs must be http:// or https:// only
- ✅ Colors must be hex format only
- ✅ Text fields have length limits enforced
- ✅ No secrets are logged

