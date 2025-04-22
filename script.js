//Theme Switch

document.addEventListener("DOMContentLoaded", () => {
  const themeToggle = document.getElementById('themeToggle');
  const body = document.body;
  const chatFrame = document.getElementById('chatFrame'); // Assuming the chat frame exists in some HTMLs

  // Load saved theme from localStorage or set default to 'light'
  const savedTheme = localStorage.getItem('theme') || 'light';
  body.setAttribute('data-theme', savedTheme);

  if (chatFrame) {
      chatFrame.src = savedTheme === 'dark' ? chatFrame.dataset.darkSrc : chatFrame.dataset.lightSrc;
  }

  themeToggle.addEventListener('click', () => {
      const isDark = body.getAttribute('data-theme') === 'dark';
      const newTheme = isDark ? 'light' : 'dark';
      
      body.setAttribute('data-theme', newTheme);
      localStorage.setItem('theme', newTheme);

      if (chatFrame) {
          chatFrame.src = newTheme === 'dark' ? chatFrame.dataset.darkSrc : chatFrame.dataset.lightSrc;
      }
  });
});

//Mobile Menu toggle

document.querySelector('.menu-btn').addEventListener('click', function() {
  document.querySelector('.nav-links').classList.toggle('active');
  document.querySelector('main').classList.toggle('slide-down');
});




document.addEventListener('click', (e) => {
if (!menuBtn.contains(e.target) && !navLinks.contains(e.target)) {
  navLinks.classList.remove('active');
}
});