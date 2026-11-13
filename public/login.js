const form = document.getElementById('login-form');
const password = document.getElementById('login-password');
const button = document.getElementById('login-btn');
const status = document.getElementById('login-status');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  button.disabled = true;
  status.textContent = 'Signing in...';
  try {
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-ares-request': 'dashboard' },
      body: JSON.stringify({ password: password.value })
    });
    const body = await response.json();
    if (!response.ok) throw new Error(body.error || 'Sign in failed. Try again.');
    password.value = '';
    window.location.replace('/');
  } catch (error) {
    password.value = '';
    status.textContent = String(error?.message ?? error);
    password.focus();
  } finally {
    button.disabled = false;
  }
});
