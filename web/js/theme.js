// Tema ilk boyamadan önce uygulanır (modül değil, eşzamanlı). Varsayılan koyu; açık tema yalnızca seçilince.
(function () {
  var t = 'dark';
  try { if (localStorage.getItem('kut-theme') === 'light') t = 'light'; } catch (e) { /* depolama yok */ }
  document.documentElement.dataset.theme = t;
})();
