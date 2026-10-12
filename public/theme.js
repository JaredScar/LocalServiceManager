// Applies the saved theme before the page paints, so there's no flash.
(function () {
  var mode = 'dark';
  try {
    var saved = localStorage.getItem('svcdash.theme');
    if (saved === 'dark' || saved === 'light' || saved === 'auto') mode = saved;
  } catch (e) {
    /* storage unavailable */
  }
  document.documentElement.setAttribute('data-theme', mode);
})();
