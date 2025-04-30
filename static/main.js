document.addEventListener('DOMContentLoaded', () => {
  const analyzeBtn = document.getElementById('analyze-btn');
  const resultDiv = document.getElementById('result');
  const loader = document.getElementById('loader');
  const passwordInput = document.getElementById('password');
  const togglePasswordIcon = document.getElementById('toggle-password');

  // Toggle show/hide password
  togglePasswordIcon.addEventListener('click', () => {
    const isPassword = passwordInput.type === 'password';
    passwordInput.type = isPassword ? 'text' : 'password';
  });

  // Analyze button logic
  analyzeBtn.addEventListener('click', async () => {
    const password = passwordInput.value;
    const securityLevel = document.getElementById('security-level').value;

    if (!password) {
      showFeedback("Please enter a password.", "red");
      return;
    }

    loader.style.display = 'block';
    resultDiv.innerHTML = '';

    try {
      const response = await fetch('/analyze', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          password: password,
          security_level: securityLevel
        })
      });

      const data = await response.json();
      loader.style.display = 'none';

      if (response.ok) {
        let feedbackHtml = `<div class="feedback ${data.strength_color}"><h3>Feedback:</h3><ul>`;
        data.strength_feedback.forEach(msg => {
          feedbackHtml += `<li>${msg}</li>`;
        });
        feedbackHtml += `</ul>`;

        if (data.breached) {
          feedbackHtml += `<p>⚠️ Password found in ${data.breach_count} breaches!</p>`;
        } else {
          feedbackHtml += `<p>✅ Password is not found in breach databases.</p>`;
        }

        feedbackHtml += `</div>`;
        resultDiv.innerHTML = feedbackHtml;
      } else {
        showFeedback(data.error, "red");
      }
    } catch (error) {
      loader.style.display = 'none';
      console.error('Error:', error);
      showFeedback("An unexpected error occurred. Please try again.", "red");
    }
  });

  function showFeedback(message, color) {
    resultDiv.innerHTML = `<div class="feedback ${color}">${message}</div>`;
  }
});
