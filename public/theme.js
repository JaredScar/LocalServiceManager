// The dashboard is the light layout shown in the product screens.
(function () {
  document.documentElement.setAttribute('data-theme', 'light');
  try {
    localStorage.removeItem('svcdash.theme');
  } catch (e) {
    /* storage unavailable */
  }
})();
