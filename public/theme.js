// Applies the saved theme before first paint. A click stores the choice;
// with nothing saved, the page follows the operating system.
(function () {
  const KEY = 'svcdash.theme';

  function saved() {
    try {
      const value = localStorage.getItem(KEY);
      return value === 'dark' || value === 'light' ? value : null;
    } catch (e) {
      return null;
    }
  }

  function preferred() {
    const choice = saved();
    if (choice) return choice;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }

  function apply(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    const meta = document.querySelector('meta[name="theme-color"]');
    if (meta) meta.setAttribute('content', theme === 'dark' ? '#121418' : '#f4f5f7');
    const btn = document.getElementById('theme');
    if (btn) {
      const dark = theme === 'dark';
      btn.setAttribute('aria-pressed', String(dark));
      btn.setAttribute('aria-label', dark ? 'Switch to light mode' : 'Switch to dark mode');
    }
  }

  apply(preferred());

  document.addEventListener('DOMContentLoaded', () => {
    apply(document.documentElement.getAttribute('data-theme') || preferred());
    const btn = document.getElementById('theme');
    if (btn) {
      btn.addEventListener('click', () => {
        const next = document.documentElement.getAttribute('data-theme') === 'dark' ? 'light' : 'dark';
        try {
          localStorage.setItem(KEY, next);
        } catch (e) {
          /* storage unavailable; the choice lasts for this page view */
        }
        apply(next);
      });
    }
    const mq = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)');
    if (mq && mq.addEventListener) {
      mq.addEventListener('change', () => {
        if (!saved()) apply(preferred());
      });
    }
  });
})();
