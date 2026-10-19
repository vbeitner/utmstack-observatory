/* UTMStack Observatory sign-in page. Copyright (c) 2026 Victor Beitner. All rights reserved. See LICENSE.
   The sign-in token arrives in the link's #fragment, which browsers never send to a server, and it is only spent
   when the person clicks Continue: mail scanners that open links ahead of the reader cannot use it up. */
(function(){
  'use strict';
  function $(s){ return document.querySelector(s); }
  var views = ['#vLink', '#vSent', '#vVerify', '#vPass'], status = {link: false, password: true}, token = '';

  function show(v){
    views.forEach(function(id){ $(id).hidden = id !== v; });
    var alt = $('#alt');
    if(v === '#vLink' && status.password){ alt.hidden = false; $('#altBtn').textContent = 'Sign in with the administrator password'; }
    else if(v === '#vPass' && status.link){ alt.hidden = false; $('#altBtn').textContent = 'Sign in with an email link instead'; }
    else alt.hidden = true;
    var first = document.querySelector(v+' input, '+v+' .primary');
    if(first) first.focus();
  }
  function note(text, kind){ var n = $('#note'); n.textContent = text || ''; n.className = 'note' + (kind ? ' '+kind : ''); }
  function post(path, body){
    return fetch(path, {method: 'POST', cache: 'no-store', credentials: 'same-origin',
      headers: {'Content-Type': 'application/json', 'X-Observatory': '1'}, body: JSON.stringify(body || {})})
      .then(function(r){ return r.json().catch(function(){ return {}; }).then(function(j){ return {status: r.status, j: j}; }); });
  }
  function home(){ location.replace('/'); }
  function startView(){
    if(status.link) show('#vLink');
    else {
      show('#vPass');
      if(!status.password){ $('#passText').textContent = 'Sign-in is not set up yet. Ask your administrator.'; }
      else $('#passText').textContent = 'Email sign-in is not set up yet, so use the installer\'s username and password.';
    }
  }

  $('#linkForm').addEventListener('submit', function(e){
    e.preventDefault();
    var email = $('#email').value.trim();
    if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)){ note('Enter a valid email address.', 'bad'); return; }
    $('#linkBtn').disabled = true; note('Sending…');
    post('/auth/request', {email: email}).then(function(r){
      $('#linkBtn').disabled = false;
      if(r.status !== 200){ note(r.j.error || ('Could not send (HTTP '+r.status+')'), 'bad'); return; }
      note('');
      $('#sentText').textContent = 'If ' + email + ' has access, a sign-in link is on its way. It works once and expires in ' +
        (r.j.minutes || 15) + ' minutes. Open it in this browser or any other.';
      show('#vSent');
    }).catch(function(){ $('#linkBtn').disabled = false; note('The dashboard is not reachable.', 'bad'); });
  });
  $('#again').addEventListener('click', function(){ note(''); show('#vLink'); });

  $('#verifyBtn').addEventListener('click', function(){
    $('#verifyBtn').disabled = true; note('Signing in…');
    post('/auth/verify', {token: token}).then(function(r){
      if(r.status === 200){ note('Signed in.', 'good'); home(); return; }
      token = '';
      note(r.j.error || ('Sign-in failed (HTTP '+r.status+')'), 'bad');
      $('#verifyBtn').disabled = false;
      startView();
    }).catch(function(){ $('#verifyBtn').disabled = false; note('The dashboard is not reachable.', 'bad'); });
  });

  $('#passForm').addEventListener('submit', function(e){
    e.preventDefault();
    $('#passBtn').disabled = true; note('Signing in…');
    post('/auth/password', {user: $('#user').value, password: $('#pass').value}).then(function(r){
      $('#passBtn').disabled = false;
      if(r.status === 200){ note('Signed in.', 'good'); home(); return; }
      $('#pass').value = '';
      note(r.j.error || ('Sign-in failed (HTTP '+r.status+')'), 'bad');
    }).catch(function(){ $('#passBtn').disabled = false; note('The dashboard is not reachable.', 'bad'); });
  });

  $('#altBtn').addEventListener('click', function(){ note(''); show($('#vLink').hidden ? '#vLink' : '#vPass'); });

  function takeToken(){
    var m = /[#&]t=([A-Za-z0-9_-]{20,100})/.exec(location.hash);
    if(!m) return false;
    token = m[1];
    try { history.replaceState(null, '', '/login'); } catch(e){}   // keep the token out of history and bookmarks
    return true;
  }
  takeToken();
  // a link pasted into a tab already on this page changes only the #fragment: no reload
  window.addEventListener('hashchange', function(){ if(takeToken()){ note(''); show('#vVerify'); } });
  fetch('/auth/status', {cache: 'no-store'}).then(function(r){ return r.json(); }).then(function(s){
    status = s;
    if(!s.login){ home(); return; }
    if(token) show('#vVerify'); else startView();
  }).catch(function(){ if(token) show('#vVerify'); else show('#vPass'); note('The dashboard is not reachable.', 'bad'); });
})();
