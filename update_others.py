import re

def update_others():
    for fname in ['garuda.html', 'garuda-landing.html']:
        try:
            with open(fname, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # garuda.html apiFetch
            old_fetch_garuda = """  if (body && typeof body.success === 'boolean') {
    if (!body.success) {
      const err = body.error || ('HTTP ' + res.status);
      throw new Error(err);
    }
    return body.data;
  }"""
            new_fetch_garuda = """  if (body && typeof body.success === 'boolean') {
    if (!body.success) {
      const err = body.error || ('HTTP ' + res.status);
      showToast(err, 'error');
      throw new Error(err);
    }
    return body.data;
  }"""
            if old_fetch_garuda in content:
                content = content.replace(old_fetch_garuda, new_fetch_garuda)
            
            # Also replace any showApiToast with showToast in garuda.html
            content = content.replace("showApiToast(", "showToast(")
            
            with open(fname, 'w', encoding='utf-8') as f:
                f.write(content)
        except Exception as e:
            print("Failed for", fname, e)

update_others()
