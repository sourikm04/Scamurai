//Theme Switch

document.addEventListener("DOMContentLoaded", () => {
  const themeToggle = document.getElementById('themeToggle');
  const body = document.body;

  const savedTheme = localStorage.getItem('theme') || 'light';
  body.setAttribute('data-theme', savedTheme);

  themeToggle.addEventListener('click', () => {
      const newTheme = body.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
      body.setAttribute('data-theme', newTheme);

      localStorage.setItem('theme', newTheme);
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