/* KUBO · monta os cubos (.kcube) e inclina o cubo [data-tilt] seguindo o mouse */
(function () {
  var R = ['rotateY(0)', 'rotateY(90deg)', 'rotateY(180deg)', 'rotateY(-90deg)', 'rotateX(90deg)', 'rotateX(-90deg)'];
  function faces(parent, cls) {
    R.forEach(function (r) {
      var f = document.createElement('i');
      f.className = cls;
      f.style.transform = r + ' translateZ(var(--hh))';
      parent.appendChild(f);
    });
  }
  function build(el) {
    if (el.children.length) return;
    var t = document.createElement('div'), fl = document.createElement('div'), inn = document.createElement('div'), core = document.createElement('div');
    t.className = 'kc-t'; fl.className = 'kc-fl'; inn.className = 'kc-in'; core.className = 'kc-core';
    faces(inn, 'kc-f'); faces(core, 'kc-c');
    inn.appendChild(core); fl.appendChild(inn); t.appendChild(fl); el.appendChild(t);
    el.setAttribute('aria-hidden', 'true');
  }
  function init() {
    var cubes = [].slice.call(document.querySelectorAll('.kcube'));
    cubes.forEach(build);
    var tilt = cubes.filter(function (c) { return c.hasAttribute('data-tilt'); }).map(function (c) { return c.children[0]; });
    if (!tilt.length || (window.matchMedia && matchMedia('(prefers-reduced-motion: reduce)').matches)) return;
    addEventListener('pointermove', function (e) {
      var x = e.clientX / innerWidth - 0.5, y = e.clientY / innerHeight - 0.5;
      tilt.forEach(function (t) {
        t.style.setProperty('--ry', (x * 50).toFixed(1) + 'deg');
        t.style.setProperty('--rx', (-y * 40).toFixed(1) + 'deg');
      });
    }, { passive: true });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init); else init();
})();
