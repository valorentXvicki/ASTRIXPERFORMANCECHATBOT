document.addEventListener('DOMContentLoaded', () => {
  // --- Constants and Global Setup ---
  const GOOGLE_CLIENT_ID = 'YOUR_GOOGLE_CLIENT_ID'; // Centralized constant
  const API_BASE_URL = 'http://localhost:3000';

  // --- Helper Functions ---
  const handleApiResponse = (response, result, successCallback, errorCallback) => {
    if (response.ok && result.token) {
      localStorage.setItem('authToken', result.token);
      window.location.href = "newcode.html";
    } else {
      errorCallback(result.error || "An unknown error occurred.");
    }
  };

  const updatePasswordStrength = (passwordInput, strengthIndicator) => {
    const val = passwordInput.value;
    let score = 0;
    let strengthText = '';
    let color = '';

    if (!val) {
      strengthIndicator.innerHTML = '';
      return;
    }

    if (val.length >= 8) score++;
    if (/[A-Z]/.test(val)) score++;
    if (/[a-z]/.test(val)) score++;
    if (/[0-9]/.test(val)) score++;
    if (/[^A-Za-z0-9]/.test(val)) score++;

    switch (score) {
      case 0:
      case 1:
        strengthText = 'Very Weak'; color = '#ff4d4d'; break;
      case 2:
        strengthText = 'Weak'; color = '#ff944d'; break;
      case 3:
        strengthText = 'Moderate'; color = '#ffd11a'; break;
      case 4:
        strengthText = 'Strong'; color = '#99e600'; break;
      case 5:
        strengthText = 'Very Strong'; color = '#00ffaa'; break;
      default:
        strengthText = ''; color = ''; break;
    }

    strengthIndicator.textContent = `Strength: ${strengthText}`;
    strengthIndicator.style.color = color;
  };

  // --- Google Sign-In Handler (shared by login and signup) ---
  async function handleGoogleLogin(googleUser) {
    const id_token = googleUser.credential;
    const errorMsgEl = document.getElementById("errorMsg"); // Assumes login page for errors

    if (errorMsgEl) errorMsgEl.style.display = "none";

    try {
      const response = await fetch(`${API_BASE_URL}/auth/google`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id_token })
      });
      const result = await response.json();
      handleApiResponse(response, result,
        () => {}, // Success is handled by redirection
        (errorText) => {
          if (errorMsgEl) {
            errorMsgEl.textContent = errorText;
            errorMsgEl.style.display = "block";
          } else {
            alert(errorText); // Fallback for signup page
          }
        }
      );
    } catch (error) {
      console.error("Error during Google login:", error);
      const errorText = "An error occurred during Google login.";
      if (errorMsgEl) {
        errorMsgEl.textContent = errorText;
        errorMsgEl.style.display = "block";
      } else {
        alert(errorText);
      }
    }
  }

  // --- Initialize Google SDK (if on a page that needs it) ---
  if (document.getElementById('google-login-btn') || document.getElementById('google-signup-btn')) {
    window.onload = () => {
      if (typeof google !== 'undefined') {
        google.accounts.id.initialize({
          client_id: GOOGLE_CLIENT_ID,
          callback: handleGoogleLogin
        });
      } else {
        console.error("Google SDK not loaded.");
      }
    };
  }

  // --- Login Page Logic ---
  const loginForm = document.getElementById("loginForm");
  if (loginForm) {
    const errorMsg = document.getElementById("errorMsg");

    loginForm.addEventListener("submit", async function(e) {
      e.preventDefault();
      errorMsg.style.display = "none";

      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;

      try {
        const response = await fetch(`${API_BASE_URL}/login`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email, password })
        });
        const result = await response.json();
        handleApiResponse(response, result,
          () => {},
          (errorText) => {
            errorMsg.textContent = errorText || "Invalid email or password";
            errorMsg.style.display = "block";
          }
        );
      } catch (error) {
        errorMsg.textContent = "Could not connect to server.";
        errorMsg.style.display = "block";
      }
    });

    document.getElementById('google-login-btn').addEventListener('click', (e) => {
      e.preventDefault();
      google.accounts.id.prompt();
    });

    document.getElementById('github-login-btn').addEventListener('click', (e) => {
      e.preventDefault();
      window.open(`${API_BASE_URL}/auth/github`, 'github-login', 'width=600,height=700');
    });
  }

  // --- Signup Page Logic ---
  const signupForm = document.getElementById("signupForm");
  if (signupForm) {
    const passwordInput = document.getElementById('password');
    const strengthIndicator = document.getElementById('password-strength');
    if (passwordInput && strengthIndicator) {
      passwordInput.addEventListener('input', () => updatePasswordStrength(passwordInput, strengthIndicator));
    }

    signupForm.addEventListener("submit", async function(e) {
      e.preventDefault();

      const username = document.getElementById("username").value;
      const email = document.getElementById("email").value;
      const password = document.getElementById("password").value;

      const response = await fetch(`${API_BASE_URL}/signup`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, email, password })
      });

      const result = await response.json();
      alert(result.message || result.error);
      if (response.ok) {
        window.location.href = "login.html";
      }
    });

    document.getElementById('google-signup-btn').addEventListener('click', (e) => {
      e.preventDefault();
      google.accounts.id.prompt();
    });

    document.getElementById('github-signup-btn').addEventListener('click', (e) => {
      e.preventDefault();
      window.open(`${API_BASE_URL}/auth/github`, 'github-login', 'width=600,height=700');
    });
  }

  // --- Forgot Password Page Logic ---
  const forgotPasswordForm = document.getElementById("forgotPasswordForm");
  if (forgotPasswordForm) {
    const messageEl = document.getElementById("message");

    forgotPasswordForm.addEventListener("submit", async function(e) {
      e.preventDefault();
      messageEl.style.display = "none";
      messageEl.classList.remove('error');

      const email = document.getElementById("email").value;
      const submitButton = e.target.querySelector('button');
      submitButton.disabled = true;
      submitButton.textContent = 'Sending...';

      try {
        const response = await fetch(`${API_BASE_URL}/forgot-password`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email })
        });
        const result = await response.json();

        if (response.ok) {
          messageEl.style.color = '#00ffaa';
          messageEl.textContent = result.message || "If an account with that email exists, a reset link has been sent.";
        } else {
          messageEl.style.color = '#ff4d4d';
          messageEl.textContent = result.error || "An error occurred. Please try again.";
        }
      } catch (error) {
        messageEl.style.color = '#ff4d4d';
        messageEl.textContent = "Could not connect to the server. Please try again later.";
      }

      messageEl.style.display = "block";
      submitButton.disabled = false;
      submitButton.textContent = 'Send Reset Link';
    });
  }

  // --- Reset Password Page Logic ---
  const resetPasswordForm = document.getElementById("resetPasswordForm");
  if (resetPasswordForm) {
    const passwordInput = document.getElementById('password');
    const strengthIndicator = document.getElementById('password-strength');
    if (passwordInput && strengthIndicator) {
      passwordInput.addEventListener('input', () => updatePasswordStrength(passwordInput, strengthIndicator));
    }

    const messageEl = document.getElementById("message");
    const urlParams = new URLSearchParams(window.location.search);
    const token = urlParams.get('token');

    if (!token) {
      messageEl.textContent = "Invalid or missing reset token.";
      messageEl.style.display = "block";
      resetPasswordForm.style.display = 'none';
    }

    resetPasswordForm.addEventListener("submit", async function(e) {
      e.preventDefault();
      messageEl.style.display = "none";

      const password = document.getElementById("password").value;
      const confirmPassword = document.getElementById("confirmPassword").value;

      if (password !== confirmPassword) {
        messageEl.textContent = "Passwords do not match.";
        messageEl.style.display = "block";
        return;
      }

      try {
        const response = await fetch(`${API_BASE_URL}/reset-password`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ token, password })
        });
        const result = await response.json();

        if (response.ok) {
          messageEl.style.color = '#00ffaa';
          messageEl.textContent = result.message || "Password has been reset successfully!";
          messageEl.style.display = "block";
          setTimeout(() => { window.location.href = 'login.html'; }, 3000);
        } else {
          messageEl.textContent = result.error || "Failed to reset password. The link may be invalid or expired.";
          messageEl.style.display = "block";
        }
      } catch (error) {
        messageEl.textContent = "An error occurred. Please try again.";
        messageEl.style.display = "block";
      }
    });
  }
});
