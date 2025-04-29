document.addEventListener('DOMContentLoaded', () => {
    const analyzeBtn = document.getElementById('analyze-btn');
    const resultDiv = document.getElementById('result');
    const loader = document.getElementById('loader');
  
    analyzeBtn.addEventListener('click', async () => {
      const password = document.getElementById('password').value;
      const securityLevel = document.getElementById('security-level').value;
  
      if (!password) {
        showError("Please enter a password.");
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
          let feedbackHtml = `<div class="success"><h3>Feedback:</h3><ul>`;
          data.strength_feedback.forEach(msg => {
            feedbackHtml += `<li>${msg}</li>`;
          });
          feedbackHtml += `</ul>`;
  
          if (data.breached) {
            feedbackHtml += `<p>⚠️ Password found in ${data.breach_count} breaches!</p>`;
          } else {
            feedbackHtml += `<p>✅ Password is safe in breach databases.</p>`;
          }
          feedbackHtml += `</div>`;
  
          resultDiv.innerHTML = feedbackHtml;
        } else {
          showError(data.error);
        }
      } catch (error) {
        loader.style.display = 'none';
        console.error('Error:', error);
        showError("An unexpected error occurred. Please try again later.");
      }
    });
  
    function showError(message) {
      resultDiv.innerHTML = `<div class="error">${message}</div>`;
    }
  });
  